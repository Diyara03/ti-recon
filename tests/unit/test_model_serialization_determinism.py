"""Set fields serialize in one order, always (Task 3 base).

A ``frozenset`` has no order and JSON has only lists, so pydantic emits whatever
the hash table iterates — which depends on the interpreter's hash seed and, for
colliding members, on insertion order. Two consequences, both load-bearing here:

* a stored result must round-trip. Reading one back and re-serializing rebuilds
  the set from a list, in a different order than the original union produced;
* this repository proves that qualification, fusion and readiness are
  re-derivable by comparing serialized results. A byte comparison against a dump
  made in another process is meaningless if the same content can serialize two
  ways.
"""

from __future__ import annotations

import json
import subprocess
import sys

from ti_recon.enums import ProviderCapability
from ti_recon.models.base import FrozenTiReconModel, TiReconModel


class _Holder(TiReconModel):
    capabilities: frozenset[ProviderCapability] = frozenset()
    names: frozenset[str] = frozenset()


class _Frozen(FrozenTiReconModel):
    capabilities: frozenset[ProviderCapability] = frozenset()


_MEMBERS = (
    ProviderCapability.REPUTATION,
    ProviderCapability.MALWARE_INTELLIGENCE,
    ProviderCapability.THREAT_ASSOCIATIONS,
    ProviderCapability.FILE_BEHAVIOR,
)


def test_a_set_field_round_trips_byte_identically() -> None:
    """The failure that started this: rebuild from JSON, dump again, compare.

    The rebuilt set is filled from a list rather than by union, so before this
    was fixed the two dumps could differ whenever two members collided.
    """
    original = _Holder(capabilities=frozenset(_MEMBERS))
    dumped = original.model_dump_json()

    restored = _Holder.model_validate_json(dumped)

    assert restored.model_dump_json() == dumped
    assert restored == original


def test_insertion_order_does_not_reach_the_serialized_form() -> None:
    """Same members, four different construction paths, one dump."""
    union = frozenset({_MEMBERS[0]}) | {_MEMBERS[1]} | {_MEMBERS[2]} | {_MEMBERS[3]}
    dumps = {
        _Holder(capabilities=frozenset(_MEMBERS)).model_dump_json(),
        _Holder(capabilities=frozenset(reversed(_MEMBERS))).model_dump_json(),
        _Holder(capabilities=union).model_dump_json(),
        _Holder(capabilities=frozenset(sorted(_MEMBERS, key=lambda x: x.value))).model_dump_json(),
    }

    assert len(dumps) == 1


def test_a_frozen_model_is_ordered_too() -> None:
    """Provider facts are the ones most likely to be stored and compared."""
    dumped = _Frozen(capabilities=frozenset(_MEMBERS)).model_dump_json()

    assert json.loads(dumped)["capabilities"] == sorted(item.value for item in _MEMBERS)


def test_python_mode_still_hands_back_a_set() -> None:
    """Only the serialized form is ordered.

    Everything that reasons over these fields in memory does set algebra with
    them, and turning one into a list would change how the engine behaves rather
    than only how it prints.
    """
    dumped = _Holder(capabilities=frozenset(_MEMBERS)).model_dump()

    assert isinstance(dumped["capabilities"], frozenset | set)
    assert dumped["capabilities"] == frozenset(_MEMBERS)


def test_two_processes_serialize_one_value_identically() -> None:
    """The cross-process half, which a single-process test cannot see.

    Hash randomization is per interpreter, so this is the only way to catch the
    ordering that made a stored dump incomparable with a fresh one.
    """
    script = (
        "from ti_recon.models.base import TiReconModel;"
        "from ti_recon.enums import ProviderCapability as P;"
        "M=type('M',(TiReconModel,),{'__annotations__':{'c':frozenset[P]}});"
        "print(M(c=frozenset({P.REPUTATION,P.MALWARE_INTELLIGENCE,"
        "P.THREAT_ASSOCIATIONS,P.FILE_BEHAVIOR})).model_dump_json())"
    )
    outputs = {
        subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
            env={"PYTHONHASHSEED": str(seed), "PATH": "/usr/bin:/bin"},
        ).stdout.strip()
        for seed in (1, 2, 3, 4, 5, 6, 7, 8)
    }

    assert len(outputs) == 1

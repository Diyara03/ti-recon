"""A pivot target must be exactly what the normalizer would make of it (Task 24 Phase 3).

Provider normalizers build related objects from provider text and do less than
the analyst-facing normalizer: an upper-case domain, a host with a space, a
URL with an unsupported scheme. Sending such a value to a third party would
disclose something TI Recon would have refused from an analyst, so a target
that does not normalize to itself is skipped, fail-closed, before any privacy
rule is consulted.
"""

from __future__ import annotations

import pytest

from ti_recon.correlation.pivots import is_canonical_observable
from ti_recon.correlation.policy import PivotSkipReason
from ti_recon.enums import IntelObjectType, ObjectClass
from ti_recon.models.intel_object import IntelObject


def _node(object_type: IntelObjectType, value: str) -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=object_type,
        canonical_value=value,
        display_value=value,
    )


@pytest.mark.parametrize(
    ("object_type", "value"),
    [
        (IntelObjectType.DOMAIN_NAME, "UPPER.EXAMPLE"),
        (IntelObjectType.DOMAIN_NAME, "has space.example"),
        (IntelObjectType.DOMAIN_NAME, "203.0.113.7:443"),
        (IntelObjectType.DOMAIN_NAME, "bücher.example"),
        (IntelObjectType.URL, "javascript:alert(1)"),
        (IntelObjectType.URL, "hxxp://example[.]com/a"),
        (IntelObjectType.URL, "https://example.com/\x1b[31m"),
        (IntelObjectType.IPV6_ADDR, "fe80::1%eth0"),
    ],
)
def test_a_value_the_normalizer_would_change_or_refuse_is_not_a_pivot_target(
    object_type: IntelObjectType, value: str
) -> None:
    assert is_canonical_observable(_node(object_type, value)) is False


@pytest.mark.parametrize(
    ("object_type", "value"),
    [
        (IntelObjectType.DOMAIN_NAME, "example.com"),
        (IntelObjectType.DOMAIN_NAME, "xn--bcher-kva.example"),
        (IntelObjectType.URL, "https://example.com/p?a=1"),
        (IntelObjectType.IPV4_ADDR, "203.0.113.7"),
        (IntelObjectType.IPV6_ADDR, "2001:db8::1"),
    ],
)
def test_a_canonical_value_passes(object_type: IntelObjectType, value: str) -> None:
    assert is_canonical_observable(_node(object_type, value)) is True


def test_the_skip_reason_exists_and_is_operational() -> None:
    assert PivotSkipReason.UNNORMALIZABLE_TARGET.value == "unnormalizable_target"

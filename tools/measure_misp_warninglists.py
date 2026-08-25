"""Measure what a warninglist profile costs to load and to query.

A reporting tool, not a test. Deliberately not a pytest assertion with a
wall-clock threshold: those fail on a loaded CI box and teach everyone to rerun
until green. This prints numbers a human decides about.

.. code-block:: bash

    uv run python tools/measure_misp_warninglists.py
    uv run python tools/measure_misp_warninglists.py --profile full

Reports disk footprint, list and entry counts, applicable counts per observable
family, the largest retained lists, retained heap, cold-load time and repeated
lookup latency. Retained heap is measured with ``tracemalloc`` after a
collection, because the resident high-water mark is dominated by JSON parsing
that has already been freed — reporting RSS would overstate the cost of the
loaded dataset by an order of magnitude.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import statistics
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Final

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from ti_recon.enums import (  # noqa: E402
    IntelObjectType,
    ObjectClass,
    ProviderCapability,
    ProviderOperation,
)
from ti_recon.models.intel_object import IntelObject  # noqa: E402
from ti_recon.normalization import normalize_observable  # noqa: E402
from ti_recon.providers import ProviderRequest  # noqa: E402
from ti_recon.providers.misp_warninglists import (  # noqa: E402
    DEFAULT_SNAPSHOT_ROOT,
    MispWarningListsAdapter,
    MispWarningListsConfig,
    core_profile,
    full_profile,
    load_snapshot,
)

EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"

FAMILIES: Final[dict[str, frozenset[str]]] = {
    "ipv4/ipv6": frozenset({"ip-src", "ip-dst"}),
    "domain": frozenset({"domain", "hostname"}),
    "url": frozenset({"url", "uri", "hostname"}),
    "file": frozenset({"md5", "sha1", "sha256"}),
}


def _request(subject: str | IntelObject) -> ProviderRequest:
    target = (
        subject if isinstance(subject, IntelObject) else normalize_observable(subject).intel_object
    )
    return ProviderRequest(
        investigation_id="measure",
        intel_object=target,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
    )


def _file(digest: str) -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=digest,
        display_value=digest,
        properties={"hashes": {"MD5": digest}},
    )


def _disk_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _time_lookups(adapter: MispWarningListsAdapter, request: ProviderRequest, reps: int) -> float:
    """Median microseconds per lookup.

    Median rather than mean: one scheduler hiccup should not become the headline
    number, and the distribution here is tight apart from outliers.
    """
    samples: list[float] = []
    for _ in range(reps):
        started = time.perf_counter()
        asyncio.run(adapter.lookup(request, None))
        samples.append((time.perf_counter() - started) * 1e6)
    return statistics.median(samples)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ or "")
    parser.add_argument("--snapshot-dir", type=Path, default=DEFAULT_SNAPSHOT_ROOT)
    parser.add_argument("--profile", choices=("core", "full"), default="core")
    parser.add_argument("--reps", type=int, default=200)
    args = parser.parse_args(argv)

    root = args.snapshot_dir.expanduser().resolve()
    if not (root / "manifest.json").is_file():
        print(f"error: no snapshot at {root}", file=sys.stderr)
        return 2

    manifest = load_snapshot(root).manifest
    profile = core_profile() if args.profile == "core" else full_profile()

    print("=== snapshot ===")
    print(f"  path                : {root}")
    print(f"  upstream commit     : {manifest.upstream_commit}")
    print(f"  generated at        : {manifest.generated_at.isoformat()}")
    print(f"  dataset fingerprint : {manifest.dataset_fingerprint}")
    print(f"  disk footprint      : {_disk_bytes(root) / 1048576:.1f} MB")
    print(f"  lists in snapshot   : {manifest.list_count}")
    print(f"  entries in snapshot : {manifest.entry_count:,}")
    print(
        f"  omitted at build    : {len(manifest.omitted)} lists, "
        f"{sum(item.entry_count for item in manifest.omitted):,} entries"
    )

    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    adapter = MispWarningListsAdapter(
        config=MispWarningListsConfig(snapshot_root=root), profile=profile
    )
    load_seconds = time.perf_counter() - started
    gc.collect()
    retained, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    index = adapter.index
    if index is None:
        print("error: snapshot did not load", file=sys.stderr)
        return 1

    print(f"\n=== profile '{profile.profile_id}' ===")
    print(f"  fingerprint         : {profile.fingerprint()[:32]}")
    print(f"  loaded lists        : {len(index.lists)}")
    print(f"  loaded entries      : {index.entry_count:,}")
    print(
        f"  profile-excluded    : {len(index.profile_excluded)} lists, "
        f"{sum(item.entry_count for item in index.profile_excluded):,} entries"
    )
    print(f"  unusable lists      : {len(index.unusable)}")
    print("\n  applicable per observable family:")
    for name, attributes in FAMILIES.items():
        applicable = index.applicable(attributes)
        print(
            f"    {name:<10} lists={len(applicable):>4} "
            f"entries={sum(item.entry_count for item in applicable):>9,}"
        )

    print("\n  largest retained lists:")
    for item in sorted(index.lists, key=lambda entry: -entry.entry_count)[:20]:
        print(f"    {item.entry_count:>8,}  {item.matcher:<9} {item.slug}")

    print("\n=== footprint ===")
    print(f"  retained heap       : {retained / 1048576:.1f} MB")
    print(f"  transient peak      : {peak / 1048576:.1f} MB")
    print(f"  bytes per entry     : {retained / max(index.entry_count, 1):.0f}")
    print(f"  cold load           : {load_seconds:.2f} s  (tracemalloc adds overhead)")

    print(f"\n=== lookup latency (median of {args.reps}) ===")
    for label, subject in (
        ("ipv4", "8.8.8.8"),
        ("ipv4 (no match)", "203.0.113.99"),
        ("ipv6", "2001:4860:4860::8888"),
        ("domain", "example.com"),
        ("domain (no match)", "nothing-knows-this.example"),
        ("url + host", "https://github.com/attacker/payload.exe"),
        ("file hash", _file(EMPTY_MD5)),
    ):
        median = _time_lookups(adapter, _request(subject), args.reps)
        print(f"  {label:<20} {median:8.0f} us")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

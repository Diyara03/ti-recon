"""The CIDR fast path yields exactly what :mod:`ipaddress` yields (Task 23).

Compiling the shipped snapshot's ~140,000 CIDR entries through
``ipaddress.ip_network`` was most of the local server's start-up. The fast path
parses the one canonical IPv4 spelling by hand and hands everything else to the
standard library. What has to hold is that the two never disagree — on any
entry of any shipped list, and on the awkward spellings a hand-written parser is
most likely to get wrong.
"""

from __future__ import annotations

import ipaddress
import json

import pytest

from ti_recon.providers.misp_warninglists.config import DEFAULT_SNAPSHOT_ROOT
from ti_recon.providers.misp_warninglists.matchers import parse_cidr


def _reference(entry: str) -> tuple[int, int, int, bool] | None:
    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None
    return (
        network.version,
        network.prefixlen,
        int(network.network_address),
        network.num_addresses == 1,
    )


@pytest.mark.parametrize(
    "entry",
    [
        "10.0.0.0/8",
        "192.168.1.1",
        "192.168.1.1/32",
        "192.168.1.77/24",  # host bits set: strict=False masks them
        "0.0.0.0/0",
        "255.255.255.255",
        "255.255.255.255/31",
        "1.2.3.4/0",
        "1.2.3.04",  # leading zero: refused by ipaddress since 3.9.5
        "01.2.3.4/8",
        "1.2.3",  # shorthand: refused
        "1.2.3.4.5",
        "256.1.1.1",
        "1.2.3.4/33",
        "1.2.3.4/-1",
        "1.2.3.4/",
        "/24",
        " 1.2.3.4",
        "1.2.3.4 ",
        "1.2.3.4/24 ",
        "1.2.3.4/024",
        "1.2.3.4/+24",
        "2001:db8::/32",
        "2001:db8::1",
        "::1/128",
        "::ffff:1.2.3.4",
        "fe80::1%eth0",
        "1.2.3.4/255.255.255.0",  # netmask form: ipaddress accepts it
        "1.2.3.4/0.0.0.255",  # hostmask form
        "0x1.2.3.4",
        "1.2.3.4/32/",
        "",
        "not an address",
        "1..2.3",
    ],
)
def test_the_fast_path_agrees_with_ipaddress_on_awkward_spellings(entry: str) -> None:
    assert parse_cidr(entry) == _reference(entry), entry


def test_the_fast_path_agrees_with_ipaddress_on_every_shipped_cidr_entry() -> None:
    """Every entry of every ``cidr`` list in the pinned snapshot, both ways."""
    root = DEFAULT_SNAPSHOT_ROOT
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    checked = 0
    for record in manifest["lists"]:
        path = root / "lists" / f"{record['slug']}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("type") != "cidr":
            continue
        for entry in raw["list"]:
            if not isinstance(entry, str):
                continue
            assert parse_cidr(entry) == _reference(entry), (record["slug"], entry)
            checked += 1
    assert checked > 100_000, "the snapshot should exercise the fast path at scale"

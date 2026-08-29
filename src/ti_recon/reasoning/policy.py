"""Versioned engine policy for context interpretation (Task 15).

Two things live here, and both are **TI Recon's opinions rather than anybody
else's data**: the clock-skew tolerance, and the map from an exact MISP
warninglist slug to a semantic category.

Why the warninglist map is ours
-------------------------------

Task 11 deliberately did not invent a category field. The raw upstream
warninglist schema has no authoritative semantic classification — MISP's runtime
database has categories, the CC0 dataset TI Recon pins does not — so inventing
one inside the provider would have meant fabricating provenance.

Task 15 does need the categories: "this address is a public DNS resolver" and
"this address is in a cloud range" call for different cautions. So the mapping is
made here, explicitly, as **engine policy** with a version on it, keyed on the
exact slug. Not on the list's name, not on its description, and never on a
substring: ``if "scanner" in name`` would silently reclassify a list the day
upstream reworded it, and would classify ``automated-malware-analysis`` as
scanning infrastructure because of a word.

An unmapped list is not a failure. It still produces
:attr:`ContextSignalType.WARNINGLIST_MATCH`, which is the honest answer: a
warninglist matched, and TI Recon has no category for it.

What a mapping does *not* mean
------------------------------

Nothing here certifies benignness. The upstream project describes these lists as
values associated with potential false positives, errors and mistakes — and an
organisation enables or disables lists to suit itself. A cloud range hosts
attacks. A CDN serves malware. A popular domain has a malicious path on it. An
EICAR hash is a test artifact, not an ordinary benign file. Every signal these
mappings produce is context, and none of them points anywhere.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Final

from ti_recon.reasoning.models import ContextSignalType

__all__ = [
    "CLOCK_SKEW_TOLERANCE",
    "CONTEXT_POLICY_VERSION",
    "WARNINGLIST_MAP_VERSION",
    "WARNINGLIST_SIGNAL_MAP",
    "signal_for_warninglist",
]

#: Version of the whole engine-owned interpretation policy in this module.
#:
#: Recorded on every result. Without it, re-reading a stored qualification after
#: a policy change would silently reinterpret it, and nobody would be able to
#: tell which rules produced which cue.
CONTEXT_POLICY_VERSION: Final[str] = "1.0.0"

#: Version of the slug map alone, bumped whenever a slug is added, removed or
#: recategorized. Separate from the policy version because a snapshot refresh
#: touches this and nothing else.
WARNINGLIST_MAP_VERSION: Final[str] = "1.0.0"

#: How far ahead of ``as_of`` an instant may sit before it is an issue.
#:
#: Providers and TI Recon do not share a clock, and a handful of minutes of skew
#: is ordinary. Beyond it, a timestamp in the future is a data problem worth
#: surfacing rather than one worth quietly clamping. Within it, age is floored at
#: zero and nothing is reported.
CLOCK_SKEW_TOLERANCE: Final[timedelta] = timedelta(minutes=5)

#: Exact warninglist slug -> semantic category.
#:
#: Every key is verified against the shipped Task 11 snapshot by a test, so a
#: dataset refresh that renames or drops a list fails loudly instead of quietly
#: turning a categorized signal into an uncategorized one.
#:
#: Chosen for being unambiguous and useful in a SOC, not for coverage. Lists
#: whose meaning is arguable — sinkholes, generic false-positive collections,
#: dynamic DNS, URL shorteners — are deliberately absent: they still produce
#: ``WARNINGLIST_MATCH`` with their slug, which says everything TI Recon can
#: honestly say about them.
WARNINGLIST_SIGNAL_MAP: Final[dict[str, ContextSignalType]] = {
    # ---------------------------------------------------------------- #
    # Known internet-scanning infrastructure.
    #
    # Traffic from these addresses is background internet measurement. That
    # may *explain* an observation; it never means the observation was false,
    # and a scanner host can itself be compromised.
    # ---------------------------------------------------------------- #
    "alphastrike-research-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "alphastrike-scanning": ContextSignalType.KNOWN_SCANNER,
    "bufferover-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "censys-scanning": ContextSignalType.KNOWN_SCANNER,
    "check-host-net": ContextSignalType.KNOWN_SCANNER,
    "circl-security-scanning": ContextSignalType.KNOWN_SCANNER,
    "circl-ssh-scanning": ContextSignalType.KNOWN_SCANNER,
    "coalition-signals-intelligence-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "cybergreen-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "cyberresilience-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "cypex-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "f6-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "internet-census-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "internetcleanup-scanner": ContextSignalType.KNOWN_SCANNER,
    "intrinsec-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "ipinfo-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "ipip-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "modat-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "modat-scanner": ContextSignalType.KNOWN_SCANNER,
    "netsecscan-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "netsecscan-scanning": ContextSignalType.KNOWN_SCANNER,
    "onyphe-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "onyphe-scanner": ContextSignalType.KNOWN_SCANNER,
    "palo-alto-networks-cortex-xpanse": ContextSignalType.KNOWN_SCANNER,
    "probethenet-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "rapid7-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "research-scanner-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "shadowforce-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "shadowforce-scanning": ContextSignalType.KNOWN_SCANNER,
    "shadowserver": ContextSignalType.KNOWN_SCANNER,
    "shadowserver-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "shodan-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "shodan-scanning": ContextSignalType.KNOWN_SCANNER,
    "skipa-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "stretchoid-nt-scanning": ContextSignalType.KNOWN_SCANNER,
    "umich-cse-connection-attempts": ContextSignalType.KNOWN_SCANNER,
    # ---------------------------------------------------------------- #
    # Public DNS resolvers.
    #
    # A sample contacting one is doing what almost every program does. The
    # contact stays on the graph; what changes is that it needs no exotic
    # explanation.
    # ---------------------------------------------------------------- #
    "public-dns-v4": ContextSignalType.PUBLIC_RESOLVER,
    "public-dns-v6": ContextSignalType.PUBLIC_RESOLVER,
    "public-dns-hostname": ContextSignalType.PUBLIC_RESOLVER,
    # ---------------------------------------------------------------- #
    # Private, reserved, documentation and special-use ranges.
    # ---------------------------------------------------------------- #
    "rfc1918": ContextSignalType.PRIVATE_OR_SPECIAL_USE,
    "rfc3849": ContextSignalType.PRIVATE_OR_SPECIAL_USE,
    "rfc5735": ContextSignalType.PRIVATE_OR_SPECIAL_USE,
    "rfc6598": ContextSignalType.PRIVATE_OR_SPECIAL_USE,
    "rfc6761": ContextSignalType.PRIVATE_OR_SPECIAL_USE,
    "ipv6-linklocal": ContextSignalType.PRIVATE_OR_SPECIAL_USE,
    "multicast": ContextSignalType.PRIVATE_OR_SPECIAL_USE,
    # ---------------------------------------------------------------- #
    # Shared cloud, CDN and shared-hosting infrastructure.
    #
    # The attribution problem in its usual form: the range is shared, so
    # "this address was malicious in March" says nothing about who is on it
    # today, and blocking it has bystanders.
    # ---------------------------------------------------------------- #
    "akamai": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "amazon-aws": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "bunny-net": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "cloudflare": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "fastly": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "github": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "google-gcp": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "icloud-private-relay": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "microsoft-azure": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "microsoft-azure-china": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "microsoft-azure-germany": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "microsoft-azure-us-gov": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "oracle-oci": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "ovh-cluster": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "stackpath": ContextSignalType.SHARED_CLOUD_OR_CDN,
    "zscaler": ContextSignalType.SHARED_CLOUD_OR_CDN,
    # ---------------------------------------------------------------- #
    # Popular or commonly-visited services.
    #
    # Popularity is not safety: a popular domain with a malicious path on it
    # is the living-off-trusted-sites case, and it is why the scope of a
    # match matters more here than anywhere else.
    # ---------------------------------------------------------------- #
    "cisco_top10k": ContextSignalType.POPULAR_OR_COMMON_SERVICE,
    "cloudflare-top10k": ContextSignalType.POPULAR_OR_COMMON_SERVICE,
    "google": ContextSignalType.POPULAR_OR_COMMON_SERVICE,
    "microsoft": ContextSignalType.POPULAR_OR_COMMON_SERVICE,
    "microsoft-office365": ContextSignalType.POPULAR_OR_COMMON_SERVICE,
    "microsoft-win10-connection-endpoints": ContextSignalType.POPULAR_OR_COMMON_SERVICE,
    # ---------------------------------------------------------------- #
    # Deliberate test and degenerate artifacts.
    # ---------------------------------------------------------------- #
    "eicar.com": ContextSignalType.TEST_ARTIFACT,
    "empty-hashes": ContextSignalType.EMPTY_ARTIFACT,
}


def signal_for_warninglist(slug: str) -> ContextSignalType:
    """The category for a warninglist slug, by exact match only.

    An unmapped slug is ``WARNINGLIST_MATCH`` rather than a guess. No substring
    test, no prefix rule, no regex: the slug either is a key or it is not, and a
    list TI Recon has not classified is reported as one.
    """
    return WARNINGLIST_SIGNAL_MAP.get(slug, ContextSignalType.WARNINGLIST_MATCH)

"""Credential groups.

Most providers need their own credential. A few share one: the abuse.ch
services (ThreatFox, URLhaus, MalwareBazaar) authenticate with a single
``Auth-Key``, so a user should enter it once rather than three times.

This is credential *grouping* configuration, not a provider integration — no
API host, endpoint or payload shape appears here.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "ABUSE_CH_GROUP",
    "CREDENTIAL_GROUP_MEMBERS",
    "VIRUSTOTAL_GROUP",
    "credential_group_for",
    "providers_in_group",
]

#: Shared credential group for the abuse.ch service family.
ABUSE_CH_GROUP: Final[str] = "abuse_ch"

#: Shared credential group for anything authenticated by a VirusTotal API key.
#: Google Threat Intelligence is a VirusTotal-keyed product, so an analyst who
#: has stored that key once should not be asked for it again per brand.
VIRUSTOTAL_GROUP: Final[str] = "virustotal"

#: Provider ids that share one credential, keyed by group name.
CREDENTIAL_GROUP_MEMBERS: Final[dict[str, frozenset[str]]] = {
    ABUSE_CH_GROUP: frozenset({"threatfox", "urlhaus", "malwarebazaar"}),
    VIRUSTOTAL_GROUP: frozenset({"gti", "virustotal"}),
}

_PROVIDER_TO_GROUP: Final[dict[str, str]] = {
    provider_id: group
    for group, members in CREDENTIAL_GROUP_MEMBERS.items()
    for provider_id in members
}


def credential_group_for(provider_id: str) -> str:
    """Return the credential group a provider draws its credential from.

    Providers with no shared group form a group of one named after themselves,
    so callers never need a special case for the common path.
    """
    return _PROVIDER_TO_GROUP.get(provider_id, provider_id)


def providers_in_group(credential_group: str) -> frozenset[str]:
    """Return the provider ids served by a credential group."""
    return CREDENTIAL_GROUP_MEMBERS.get(credential_group, frozenset({credential_group}))

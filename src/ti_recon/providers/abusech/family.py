"""What the three abuse.ch platforms share (Task 10).

ThreatFox, URLhaus and MalwareBazaar are three datasets, three APIs and three
adapters — but they are one ecosystem, run by one organization, authenticated by
one key, and they cross-reference each other constantly. ThreatFox points at
MalwareBazaar samples; URLhaus payload records carry MalwareBazaar and VirusTotal
references; MalwareBazaar relays a dozen sandbox vendors.

The lineage rule
----------------

Each platform is its own ``transport_provider`` and its own ``origin_provider``
for facts it observed itself, but all three share one **source family**. That is
the whole point: a fusion layer must be able to see that

    ThreatFox + URLhaus + MalwareBazaar  ≠  three independent corroborations

Within the family, each platform still keeps its own ``lineage_group_id``, so
"ThreatFox says malicious" and "URLhaus says malicious" are distinguishable
claims from a shared house — not the same claim counted twice, and not two
strangers agreeing.

Relayed data keeps its real origin
----------------------------------

When one of these APIs repeats somebody else's finding, that finding does not
become an abuse.ch fact. A VirusTotal detection count relayed through URLhaus
carries VirusTotal's origin *and VirusTotal's family* — which is the same family
a direct Google Threat Intelligence result carries, precisely so the two can
never be counted as independent. See :data:`VIRUSTOTAL_RELAY_FAMILY`.
"""

from __future__ import annotations

from typing import Final

from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.groups import ABUSE_CH_GROUP

__all__ = [
    "ABUSE_CH_AUTH_HEADER",
    "ABUSE_CH_AUTH_TYPE",
    "ABUSE_CH_CREDENTIAL_GROUP",
    "ABUSE_CH_PROVIDER_IDS",
    "ABUSE_CH_SOURCE_FAMILY",
    "BLOCKLIST_RELAY_FAMILY",
    "BLOCKLIST_RELAY_ORIGIN",
    "VENDOR_INTEL_RELAY_FAMILY",
    "VENDOR_INTEL_RELAY_ORIGIN",
    "VIRUSTOTAL_RELAY_FAMILY",
    "VIRUSTOTAL_RELAY_ORIGIN",
    "lineage_group_for",
]

#: One family for all three platforms. Two of them agreeing is one ecosystem
#: agreeing with itself, and evidence fusion has to be able to see that.
ABUSE_CH_SOURCE_FAMILY: Final[str] = "abuse_ch"

#: The Task 4 credential group all three draw from. One analyst stores one
#: Auth-Key and every abuse.ch provider can use it.
ABUSE_CH_CREDENTIAL_GROUP: Final[str] = ABUSE_CH_GROUP

#: abuse.ch authenticates with its own header name, shared across the platforms.
#: This is exactly the case :class:`~ti_recon.credentials.enums.AuthType` split
#: ``AUTH_KEY`` out from ``API_KEY`` for.
ABUSE_CH_AUTH_TYPE: Final[AuthType] = AuthType.AUTH_KEY
ABUSE_CH_AUTH_HEADER: Final[str] = "Auth-Key"

#: The provider ids in this family, for tests and for readers.
ABUSE_CH_PROVIDER_IDS: Final[frozenset[str]] = frozenset({"threatfox", "urlhaus", "malwarebazaar"})


def lineage_group_for(provider_id: str) -> str:
    """The lineage group for one platform's own first-hand facts.

    Per platform rather than per family: within the abuse.ch house, a ThreatFox
    IOC record and a URLhaus URL record are different claims from different
    datasets. Sharing a *family* already stops them being read as independent;
    sharing a *lineage group* as well would wrongly collapse them into one claim.
    """
    return f"{ABUSE_CH_SOURCE_FAMILY}:{provider_id}"


# --------------------------------------------------------------------------- #
# Relayed origins
#
# Nothing below is an abuse.ch fact. Each names the party that actually produced
# the data, so ``Evidence.is_relayed`` is true and a fusion layer can discount
# the overlap instead of counting it.
# --------------------------------------------------------------------------- #

#: The origin of a VirusTotal result repeated inside an abuse.ch response.
VIRUSTOTAL_RELAY_ORIGIN: Final[str] = "virustotal"

#: The family such a result belongs to.
#:
#: Deliberately equal to Google Threat Intelligence's own ``source_family``:
#: GTI *is* VirusTotal's data, so a VT count relayed by URLhaus and a direct GTI
#: lookup share an upstream and must never be counted as two sources. The value
#: is duplicated rather than imported because a provider package may not depend
#: on another provider package — a test asserts the two constants agree, which
#: is where a divergence would be caught.
VIRUSTOTAL_RELAY_FAMILY: Final[str] = "google_ti"

#: The origin of URL blocklist statuses (Spamhaus DBL, SURBL) that URLhaus
#: repeats. abuse.ch did not compile those lists.
BLOCKLIST_RELAY_ORIGIN: Final[str] = "url_blocklists"

#: Two providers relaying overlapping blocklists are not independent of each
#: other either, so every such aggregate shares one family.
BLOCKLIST_RELAY_FAMILY: Final[str] = "multi_blocklist_aggregate"

#: The origin of third-party sandbox and reputation output that MalwareBazaar
#: carries in ``vendor_intel``.
VENDOR_INTEL_RELAY_ORIGIN: Final[str] = "third_party_vendor_intel"

#: The family that output belongs to. A future direct sandbox integration must
#: land in this family too, so a relayed Triage verdict and a direct Triage
#: verdict cannot be read as two.
VENDOR_INTEL_RELAY_FAMILY: Final[str] = "multi_vendor_intel"

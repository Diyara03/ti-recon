"""ThreatFox provider (Task 10).

TI Recon's source of **current, vetted malware IOCs**. ThreatFox is abuse.ch's
community indicator database: addresses, domains, URLs and hashes that somebody
confirmed were being used by a malware family, with the family, its aliases and
its Malpedia reference attached.

What that buys an investigation:

* **A curated assertion** that an indicator is malware-related, with ThreatFox's
  own confidence level preserved as *its* confidence and nothing else;
* **Threat association** — the malware family an indicator belongs to, which is
  often the most useful single fact about it;
* **Infrastructure pivots** — for a file hash, the C2 addresses, domains and URLs
  ThreatFox links to that sample.

Two things are easy to get wrong and are handled explicitly here.

**An address is stored as ``ip:port``.** So an address lookup asks for a loose
match and then re-validates every record locally by parsing it: a search for
``1.2.3.4`` must never accept ``11.2.3.45:443``. A confirmed port-qualified match
is recorded as ``SAME_IP`` rather than as the address itself, and the count of
discarded records is published in the coverage evidence.

**A miss is a horizon, not an acquittal.** ThreatFox expires indicators from its
API after about six months, so "no current record" means "nothing unexpired
matched". Every result says so on its face, and an absence is never reported as
benign.

Passive throughout. Nothing here submits an indicator, downloads the IOC export,
or runs a tag, family or recent-additions query — ThreatFox offers all of those,
and the permitted query set makes them unreachable rather than merely unused.
"""

from ti_recon.providers.threatfox.adapter import (
    THREATFOX_NOT_SUPPORTED,
    UNSUPPORTED_REASONS,
    ThreatFoxAdapter,
    ThreatFoxClientFactory,
)
from ti_recon.providers.threatfox.client import (
    ALLOWED_QUERIES,
    THREATFOX_HASH_LENGTHS,
    ThreatFoxClient,
    ThreatFoxConfig,
    ThreatFoxHttpClient,
    ThreatFoxOperation,
)
from ti_recon.providers.threatfox.descriptor import (
    THREATFOX_ADAPTER_VERSION,
    THREATFOX_API_VERSION,
    THREATFOX_CAPABILITIES,
    THREATFOX_CREDENTIAL_GROUP,
    THREATFOX_ORIGIN_PROVIDER,
    THREATFOX_PROVIDER_ID,
    THREATFOX_SOURCE_FAMILY,
    THREATFOX_SUPPORTED_OBJECT_TYPES,
    build_threatfox_descriptor,
    build_threatfox_planning_profile,
)
from ti_recon.providers.threatfox.matching import (
    MatchedComponent,
    ThreatFoxMatch,
    match_for,
    split_host_port,
)
from ti_recon.providers.threatfox.normalizer import (
    IOC_EXPIRY_HORIZON_MONTHS,
    MAX_ALIASES,
    MAX_TAGS,
    ThreatFoxRecord,
    normalize_coverage,
    normalize_hash_association,
    normalize_ioc_match,
    normalize_no_current_record,
    normalize_related_samples,
    records_of,
)
from ti_recon.providers.threatfox.policy import (
    THREATFOX_NO_DATA_TTL_SECONDS,
    THREATFOX_SUCCESS_TTL_SECONDS,
    ThreatFoxLookupPolicy,
    build_threatfox_execution_policy,
)

__all__ = [
    "ALLOWED_QUERIES",
    "IOC_EXPIRY_HORIZON_MONTHS",
    "MAX_ALIASES",
    "MAX_TAGS",
    "THREATFOX_ADAPTER_VERSION",
    "THREATFOX_API_VERSION",
    "THREATFOX_CAPABILITIES",
    "THREATFOX_CREDENTIAL_GROUP",
    "THREATFOX_HASH_LENGTHS",
    "THREATFOX_NOT_SUPPORTED",
    "THREATFOX_NO_DATA_TTL_SECONDS",
    "THREATFOX_ORIGIN_PROVIDER",
    "THREATFOX_PROVIDER_ID",
    "THREATFOX_SOURCE_FAMILY",
    "THREATFOX_SUCCESS_TTL_SECONDS",
    "THREATFOX_SUPPORTED_OBJECT_TYPES",
    "UNSUPPORTED_REASONS",
    "MatchedComponent",
    "ThreatFoxAdapter",
    "ThreatFoxClient",
    "ThreatFoxClientFactory",
    "ThreatFoxConfig",
    "ThreatFoxHttpClient",
    "ThreatFoxLookupPolicy",
    "ThreatFoxMatch",
    "ThreatFoxOperation",
    "ThreatFoxRecord",
    "build_threatfox_descriptor",
    "build_threatfox_execution_policy",
    "build_threatfox_planning_profile",
    "match_for",
    "normalize_coverage",
    "normalize_hash_association",
    "normalize_ioc_match",
    "normalize_no_current_record",
    "normalize_related_samples",
    "records_of",
    "split_host_port",
]

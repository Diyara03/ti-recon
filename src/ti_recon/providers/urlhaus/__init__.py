"""URLhaus provider (Task 10).

TI Recon's source of **malware-distribution intelligence**. URLhaus is abuse.ch's
database of URLs observed serving malware payloads, and it answers three
different questions depending on what it is asked about:

* an **exact URL** it tracked — a direct assertion that this artifact served
  malware, at ``EXACT_OBSERVABLE`` scope;
* a **host** it has tracked malware URLs on — a real but narrower association at
  ``SAME_HOST`` scope, because the host may be dedicated attacker infrastructure,
  a compromised site, or shared hosting where one tenant was breached;
* a **payload** it collected from a tracked URL — provenance, and **context
  only**.

That last one is the important caveat. URLhaus collects whatever a monitored URL
served, and it says so itself: a URL that distributed malware last week may serve
an installer or an error page today. So a file's presence in URLhaus means "these
bytes came off malware-distribution infrastructure", which is genuinely useful
and is not a verdict on the file. A family signature is preserved when URLhaus
has one, but turning it into a direction here would be an adapter deciding
maliciousness on a field it cannot verify.

**Offline is not benign.** ``url_status`` says whether a URL is serving right now;
an offline malicious URL is still a malicious URL that was observed distributing
malware.

**Relayed findings stay relayed.** URLhaus repeats VirusTotal detections and
Spamhaus/SURBL statuses. Neither becomes an extra malicious signal: a VT count
relayed here carries VirusTotal's origin and the same source family a direct
Google Threat Intelligence result carries, which is what stops the two being
counted as two sources.

Passive throughout, and the URL under investigation is **never fetched** — it is
sent to URLhaus as a form value. Nothing here submits a URL, triggers a rescan,
downloads a payload or reads a feed.
"""

from ti_recon.providers.urlhaus.adapter import (
    UNSUPPORTED_REASONS,
    URLHAUS_NOT_SUPPORTED,
    UrlhausAdapter,
    UrlhausClientFactory,
    UrlhausLookupKind,
)
from ti_recon.providers.urlhaus.client import (
    ALLOWED_PATHS,
    URLHAUS_HASH_LENGTHS,
    UrlhausClient,
    UrlhausConfig,
    UrlhausHttpClient,
    UrlhausOperation,
)
from ti_recon.providers.urlhaus.descriptor import (
    URLHAUS_ADAPTER_VERSION,
    URLHAUS_API_VERSION,
    URLHAUS_CAPABILITIES,
    URLHAUS_CREDENTIAL_GROUP,
    URLHAUS_ORIGIN_PROVIDER,
    URLHAUS_PROVIDER_ID,
    URLHAUS_SOURCE_FAMILY,
    URLHAUS_SUPPORTED_OBJECT_TYPES,
    build_urlhaus_descriptor,
)
from ti_recon.providers.urlhaus.normalizer import (
    BLOCKLIST_FIELDS,
    MAX_TAGS,
    PAYLOAD_FINGERPRINT_FIELDS,
    URL_RECORD_FIELDS,
    normalize_blocklists,
    normalize_host_association,
    normalize_not_tracked,
    normalize_payload_record,
    normalize_relayed_virustotal,
    normalize_url_record,
)
from ti_recon.providers.urlhaus.policy import (
    URLHAUS_NO_DATA_TTL_SECONDS,
    URLHAUS_SUCCESS_TTL_SECONDS,
    UrlhausLookupPolicy,
    build_urlhaus_execution_policy,
)

__all__ = [
    "ALLOWED_PATHS",
    "BLOCKLIST_FIELDS",
    "MAX_TAGS",
    "PAYLOAD_FINGERPRINT_FIELDS",
    "UNSUPPORTED_REASONS",
    "URLHAUS_ADAPTER_VERSION",
    "URLHAUS_API_VERSION",
    "URLHAUS_CAPABILITIES",
    "URLHAUS_CREDENTIAL_GROUP",
    "URLHAUS_HASH_LENGTHS",
    "URLHAUS_NOT_SUPPORTED",
    "URLHAUS_NO_DATA_TTL_SECONDS",
    "URLHAUS_ORIGIN_PROVIDER",
    "URLHAUS_PROVIDER_ID",
    "URLHAUS_SOURCE_FAMILY",
    "URLHAUS_SUCCESS_TTL_SECONDS",
    "URLHAUS_SUPPORTED_OBJECT_TYPES",
    "URL_RECORD_FIELDS",
    "UrlhausAdapter",
    "UrlhausClient",
    "UrlhausClientFactory",
    "UrlhausConfig",
    "UrlhausHttpClient",
    "UrlhausLookupKind",
    "UrlhausLookupPolicy",
    "UrlhausOperation",
    "build_urlhaus_descriptor",
    "build_urlhaus_execution_policy",
    "normalize_blocklists",
    "normalize_host_association",
    "normalize_not_tracked",
    "normalize_payload_record",
    "normalize_relayed_virustotal",
    "normalize_url_record",
]

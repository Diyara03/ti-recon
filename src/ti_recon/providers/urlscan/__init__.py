"""urlscan.io provider (Task 8).

TI Recon's source of **passive web intelligence**: what urlscan's browsers
observed when they visited a page, historically and at scale. An analyst's own
urlscan API key is used, and only ever to read what urlscan already stored.

Two modes, one of which never happens by accident:

* **Enrichment** (every lookup) — historical search, bounded scan results,
  normalized page/infrastructure observations. No DOM, no screenshot, no stored
  response bodies.
* **Web forensics** (explicit only) — stored page artifacts analysed statically,
  and only when a caller asks for
  :attr:`~ti_recon.enums.ProviderCapability.WEB_FORENSICS` at DEEP depth.

Passive throughout. Nothing here submits a URL, triggers a rescan, changes a
scan's visibility, deletes anything or downloads a stored sample — urlscan can
do all of those, and this integration deliberately cannot.
"""

from ti_recon.providers.urlscan.client import (
    MAX_SEARCH_SIZE,
    UrlscanArtifact,
    UrlscanClient,
    UrlscanHttpClient,
    UrlscanJsonResult,
    UrlscanOperation,
)
from ti_recon.providers.urlscan.config import (
    URLSCAN_API_KEY_HEADER,
    URLSCAN_AUTH_TYPE,
    URLSCAN_HOST,
    UrlscanConfig,
    build_transport_config,
)
from ti_recon.providers.urlscan.descriptor import (
    URLSCAN_ADAPTER_VERSION,
    URLSCAN_API_VERSION,
    URLSCAN_CAPABILITIES,
    URLSCAN_CREDENTIAL_GROUP,
    URLSCAN_ORIGIN_PROVIDER,
    URLSCAN_PROVIDER_ID,
    URLSCAN_SOURCE_FAMILY,
    URLSCAN_SUPPORTED_OBJECT_TYPES,
    build_urlscan_descriptor,
)
from ti_recon.providers.urlscan.errors import (
    URLSCAN_STATUS_CATEGORIES,
    category_for_status,
    parse_reset_at,
    parse_retry_after,
    scrub_detail,
    translate_status_error,
)

__all__ = [
    "MAX_SEARCH_SIZE",
    "URLSCAN_ADAPTER_VERSION",
    "URLSCAN_API_KEY_HEADER",
    "URLSCAN_API_VERSION",
    "URLSCAN_AUTH_TYPE",
    "URLSCAN_CAPABILITIES",
    "URLSCAN_CREDENTIAL_GROUP",
    "URLSCAN_HOST",
    "URLSCAN_ORIGIN_PROVIDER",
    "URLSCAN_PROVIDER_ID",
    "URLSCAN_SOURCE_FAMILY",
    "URLSCAN_STATUS_CATEGORIES",
    "URLSCAN_SUPPORTED_OBJECT_TYPES",
    "UrlscanArtifact",
    "UrlscanClient",
    "UrlscanConfig",
    "UrlscanHttpClient",
    "UrlscanJsonResult",
    "UrlscanOperation",
    "build_transport_config",
    "build_urlscan_descriptor",
    "category_for_status",
    "parse_reset_at",
    "parse_retry_after",
    "scrub_detail",
    "translate_status_error",
]

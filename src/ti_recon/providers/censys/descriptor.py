"""The Censys provider descriptor (Task 9).

Separate from the adapter so the identity of the provider — its id, credential
group, supported object types and declared capabilities — can be imported and
registered without pulling in the client or the normalizer.

Naming choices worth stating:

* ``provider_id = "censys"`` is what appears as ``transport_provider`` on every
  piece of evidence: whose API we actually called.
* ``source_family = "censys"`` groups everything Censys's own scanners saw. A
  service banner, a TLS certificate, a DNS name and a reported vulnerability all
  come out of the same scan of the same asset — they are four *claims*, not four
  sources, and they share a lineage group so a fusion layer can never read them
  as independent corroboration.
* ``credential_group = "censys"`` because the credential is a Censys personal
  access token and nothing else consumes it.

What Censys is *for*, and what it is not
----------------------------------------

Censys answers "what is exposed here" — which ports respond, what software is
visible, which certificate is served, which names point at it. It does not
answer "is this malicious", and the capabilities declared here say so: there is
no ``REPUTATION`` and no ``THREAT_ASSOCIATIONS``. An exposed RDP port is not an
attacker, an outdated web server is not malware, and this descriptor is the
first place that distinction is made rather than the last.

Object types are declared narrowly and on purpose. A bare domain is **not**
declared: Censys keys a web property by ``hostname:port``, so answering for a
domain would mean picking ports on the analyst's behalf and presenting two
guesses as domain coverage. A file hash is not declared either — Censys does
index certificates by fingerprint, but a TI Recon ``file`` hash is a file hash,
and reinterpreting one as a certificate fingerprint would be a category error
that produced confident nonsense.
"""

from __future__ import annotations

from typing import Final

from ti_recon.enums import IntelObjectType, ProviderCapability
from ti_recon.providers.descriptor import ProviderDescriptor

__all__ = [
    "CENSYS_ADAPTER_VERSION",
    "CENSYS_API_VERSION",
    "CENSYS_CAPABILITIES",
    "CENSYS_CREDENTIAL_GROUP",
    "CENSYS_ORIGIN_PROVIDER",
    "CENSYS_PROVIDER_ID",
    "CENSYS_SOURCE_FAMILY",
    "CENSYS_SUPPORTED_OBJECT_TYPES",
    "build_censys_descriptor",
]

CENSYS_PROVIDER_ID: Final[str] = "censys"

#: Who produced the observation, as opposed to whose API carried it. Equal to
#: :data:`CENSYS_PROVIDER_ID`: Censys scans the internet itself, so everything
#: this integration normalizes is first-hand. If a future Censys field turns out
#: to repeat a third party's data, that field must get its own origin before it
#: becomes evidence — otherwise a relayed opinion would be indistinguishable
#: from Censys's own scan.
CENSYS_ORIGIN_PROVIDER: Final[str] = CENSYS_PROVIDER_ID

CENSYS_SOURCE_FAMILY: Final[str] = "censys"
CENSYS_CREDENTIAL_GROUP: Final[str] = "censys"

#: The Censys Platform API. The older Search API v2 is not implemented.
CENSYS_API_VERSION: Final[str] = "v3"
CENSYS_ADAPTER_VERSION: Final[str] = "0.1.0"

#: Addresses, and HTTP/HTTPS URLs that map deterministically onto a web
#: property. See :mod:`ti_recon.providers.censys.assets` for the mapping and for
#: why a bare domain is deliberately absent.
CENSYS_SUPPORTED_OBJECT_TYPES: Final[frozenset[IntelObjectType]] = frozenset(
    {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.URL,
    }
)

#: What the *integration* can technically answer.
#:
#: Infrastructure and exposure, plus the pivots that come with them. Notably
#: absent: ``REPUTATION``, ``THREAT_ASSOCIATIONS``, ``SCANNER_CONTEXT`` and
#: anything active. Censys sees what is exposed; it does not judge it, and
#: neither does this adapter.
CENSYS_CAPABILITIES: Final[frozenset[ProviderCapability]] = frozenset(
    {
        ProviderCapability.CURRENT_INFRASTRUCTURE,
        ProviderCapability.NETWORK_OWNERSHIP,
        ProviderCapability.CERTIFICATE_CONTEXT,
        ProviderCapability.RELATIONSHIPS,
    }
)


def build_censys_descriptor() -> ProviderDescriptor:
    """The static declaration registered with the provider registry.

    ``supports_active`` is ``False`` and stays that way. Censys can be asked to
    rescan an asset on demand, which is traffic sent to somebody's host on an
    analyst's behalf. That path is out of scope and unimplemented.
    """
    return ProviderDescriptor(
        provider_id=CENSYS_PROVIDER_ID,
        display_name="Censys",
        adapter_version=CENSYS_ADAPTER_VERSION,
        api_version=CENSYS_API_VERSION,
        source_family=CENSYS_SOURCE_FAMILY,
        credential_group=CENSYS_CREDENTIAL_GROUP,
        supported_object_types=CENSYS_SUPPORTED_OBJECT_TYPES,
        capabilities=CENSYS_CAPABILITIES,
        supports_passive=True,
        supports_active=False,
        supports_batch=False,
        requires_credentials=True,
    )

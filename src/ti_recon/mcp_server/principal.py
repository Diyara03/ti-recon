"""Who an authenticated remote request belongs to (Task 22).

One question: given a token an authorization server issued and TI Recon has
*already validated*, what identity does the engine below run under?

The answer is a **pseudonymous tenant identifier** — a keyed digest of the
issuer and the subject. Not anonymous, not irreversible, and not collision-free
in the mathematical sense: it identifies a person, and anyone holding the
deployment's tenant key can recompute it for a subject they can guess. What it
does buy is that the raw subject — which at real identity providers is routinely
an email address, a username or an employee number — never reaches a cache key,
a cooldown key, a metric or a credential record.

Why a keyed digest and not ``sha256(issuer + subject)``
------------------------------------------------------

A plain digest of a low-entropy value is pseudonymous only against casual
inspection. An attacker who obtains an execution scope identity, a metrics
export or a credential store dump can enumerate a corporate directory offline
and recover every analyst in minutes; email addresses and employee ids are
exactly the input a dictionary attack wants. HMAC-SHA-256 under a deployment
secret removes that: without the key there is nothing to enumerate against.

The encoding is domain-separated and length-prefixed rather than concatenated.
``iss="https://a" sub="bc"`` and ``iss="https://ab" sub="c"`` are different
principals, and a naive concatenation would make them one identifier.

Nothing is normalized
---------------------

No case folding, no trimming, no Unicode rewriting, no URL normalization. The
exact issuer and subject semantics belong to the identity provider, and a
resource server that "tidied" them would be inventing an equivalence the IdP
never stated — merging two principals, or splitting one, depending on which way
the tidying went.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from pydantic import SecretBytes

__all__ = [
    "TENANT_ID_PREFIX",
    "RemotePrincipal",
    "derive_tenant_id",
]

#: The versioned prefix every derived tenant identifier carries.
#:
#: Versioned because the derivation is a contract: Task 23 will key durable
#: credential ownership on these strings, and a change to the encoding has to be
#: visible in the identifier rather than silently producing different tenants
#: for the same people.
TENANT_ID_PREFIX = "tenant-v1:"

#: Domain separation. Ensures this HMAC can never collide with another use of
#: the same deployment key, present or future.
_TENANT_DOMAIN = b"ti-recon/remote-tenant/v1"


@dataclass(frozen=True)
class RemotePrincipal:
    """The whole identity that crosses out of the MCP layer.

    One field on purpose. The access token, the raw issuer, the raw subject, the
    OAuth ``client_id``, the token claims, an email and a display name all stop
    at the boundary that produced this object: below it, ``tenant_id`` is the
    entire vocabulary, which is what makes "did an identity leak downstream?" a
    question with a structural answer rather than an audit.
    """

    tenant_id: str


def derive_tenant_id(*, issuer: str, subject: str, tenant_key: SecretBytes) -> str:
    """The pseudonymous tenant identifier for one validated principal.

    Deterministic: the same issuer, subject and deployment key always produce the
    same identifier, with no clock and no randomness involved. That is what lets
    a returning analyst find their own credentials and their own cache entries.

    Both inputs must come from a *verified* token. Deriving from an unvalidated
    bearer string would let anybody mint any tenant they liked, which is the
    whole isolation boundary.

    ``tenant_key`` is raw key bytes, already decoded. HMAC-SHA-256 takes a key,
    not a passphrase: handing it a human-chosen string would make the security of
    every tenant identifier in the deployment equal to the guessability of that
    string, and a resource server has no business stretching a password.
    """
    message = b"".join(
        _framed(part) for part in (_TENANT_DOMAIN, issuer.encode("utf-8"), subject.encode("utf-8"))
    )
    digest = hmac.new(tenant_key.get_secret_value(), message, hashlib.sha256).hexdigest()
    return f"{TENANT_ID_PREFIX}{digest}"


def _framed(part: bytes) -> bytes:
    """One length-prefixed field, so no boundary between fields is ambiguous."""
    return len(part).to_bytes(8, "big") + part

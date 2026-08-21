"""Observable normalization (Task 3).

Turns raw analyst input into a canonical :class:`~ti_recon.models.intel_object.IntelObject`.

Design rules:

* **Syntactic only.** No DNS resolution, no WHOIS, no network I/O of any kind.
* **Conservative.** Normalization removes ambiguity that is safe to remove
  (case of a hostname, a trailing root dot, a default port) and nothing else.
  URL paths, queries and fragments are preserved byte-for-byte.
* **Lossless.** The caller keeps the original input alongside the canonical
  value, so an investigation can always show what was actually submitted.

Supported defanging
-------------------

``hxxp://`` / ``hxxps://`` scheme mangling, ``[://]`` and ``[:]//`` separators,
and ``[.]`` / ``(.)`` / ``{.}`` / ``[dot]`` dot mangling. For inputs with a
URL scheme, dot-undefanging is applied **only to the host component** — a path
or query may legitimately contain bracketed text, and rewriting it would
corrupt the very artifact under investigation.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Final
from urllib.parse import urlsplit, urlunsplit

import idna

from ti_recon.enums import IntelObjectType, ObjectClass
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.models.intel_object import (
    HASH_HEX_LENGTHS,
    IntelObject,
    hash_algorithm_for_hex_length,
)
from ti_recon.normalization.errors import NormalizationError

__all__ = [
    "MAX_INPUT_LENGTH",
    "NormalizationResult",
    "normalize_domain",
    "normalize_file_hash",
    "normalize_ip",
    "normalize_observable",
    "normalize_url",
    "undefang",
]

#: Upper bound on accepted raw input, to keep normalization cheap and bounded.
MAX_INPUT_LENGTH: Final[int] = 4096

#: Schemes accepted for ``url`` observables.
ALLOWED_URL_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https", "ftp"})

_DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443, "ftp": 21}

_HEX_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-fA-F]+\Z")

# Control characters, zero-width characters and bidi overrides.
_INVISIBLE_RE: Final[re.Pattern[str]] = re.compile(
    r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]"
)

_SCHEME_DEFANG_RE: Final[re.Pattern[str]] = re.compile(r"\Ah(?:xx|XX|tt)p(s?)\b", re.IGNORECASE)
_DOT_DEFANG_RE: Final[re.Pattern[str]] = re.compile(
    r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]", re.IGNORECASE
)
_SEPARATOR_DEFANG_RE: Final[re.Pattern[str]] = re.compile(r"\[\s*:\s*//\s*\]|\[\s*:\s*\]//")

# A single ASCII DNS label. Underscores are permitted because service records
# (``_dmarc``, ``_acme-challenge``) are legitimately observed in the wild.
_ASCII_LABEL_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(?![-])[a-z0-9_-]{1,63}\Z",
)
_TLD_RE: Final[re.Pattern[str]] = re.compile(r"\A(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})\Z")

_MAX_DOMAIN_LENGTH: Final[int] = 253


class NormalizationResult(FrozenTiReconModel):
    """A normalized observable together with the input it came from."""

    original_input: str
    intel_object: IntelObject


def undefang(raw: str) -> str:
    """Remove supported defanging from a value with no URL scheme."""
    return _DOT_DEFANG_RE.sub(".", raw)


def _undefang_scheme(raw: str) -> str:
    """Repair a defanged URL scheme and scheme separator."""
    repaired = _SEPARATOR_DEFANG_RE.sub("://", raw)
    return _SCHEME_DEFANG_RE.sub(lambda m: f"http{m.group(1).lower()}", repaired)


def _prepare(raw: str) -> str:
    """Trim, reject invisible characters, and bound the input length."""
    candidate = raw.strip()
    if not candidate:
        msg = "input is empty"
        raise NormalizationError(msg)
    if len(candidate) > MAX_INPUT_LENGTH:
        msg = f"input exceeds {MAX_INPUT_LENGTH} characters"
        raise NormalizationError(msg, input_length=len(candidate))
    if any(ch.isspace() for ch in candidate):
        msg = "input must not contain whitespace"
        raise NormalizationError(msg, input_length=len(candidate))
    if _INVISIBLE_RE.search(candidate):
        # Zero-width and bidi characters are a homograph/obfuscation vector and
        # are never legitimately part of a canonical observable.
        msg = "input contains invisible or control characters"
        raise NormalizationError(msg, input_length=len(candidate))
    return candidate


# --------------------------------------------------------------------------- #
# Hashes
# --------------------------------------------------------------------------- #


def normalize_file_hash(raw: str) -> IntelObject:
    """Normalize an MD5/SHA-1/SHA-256 hex digest into a ``file`` object."""
    candidate = _prepare(raw)
    if not _HEX_RE.fullmatch(candidate):
        msg = "hash must be hexadecimal"
        raise NormalizationError(msg)
    algorithm = hash_algorithm_for_hex_length(len(candidate))
    if algorithm is None:
        supported = sorted(HASH_HEX_LENGTHS.values())
        msg = f"hash length {len(candidate)} is not one of {supported}"
        raise NormalizationError(msg)
    digest = candidate.lower()
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=digest,
        display_value=digest,
        properties={"hashes": {algorithm: digest}},
    )


# --------------------------------------------------------------------------- #
# IP addresses
# --------------------------------------------------------------------------- #


def normalize_ip(raw: str) -> IntelObject:
    """Normalize an IPv4 or IPv6 address."""
    candidate = _prepare(raw)
    address = _parse_ip(undefang(candidate))
    if address is None:
        msg = "value is not a valid IP address"
        raise NormalizationError(msg)
    canonical = str(address)
    object_type = IntelObjectType.IPV4_ADDR if address.version == 4 else IntelObjectType.IPV6_ADDR
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=object_type,
        canonical_value=canonical,
        display_value=canonical,
    )


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    inner = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        return ipaddress.ip_address(inner)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Domains
# --------------------------------------------------------------------------- #


def normalize_domain(raw: str) -> IntelObject:
    """Normalize a domain name.

    Lowercases, strips a single trailing root dot, and converts
    internationalized names to their IDNA A-label form. The Unicode form is
    kept as ``display_value`` so analysts still see what they submitted.
    """
    candidate = _prepare(raw)
    canonical, display = _normalize_hostname(undefang(candidate))
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.DOMAIN_NAME,
        canonical_value=canonical,
        display_value=display,
    )


def _normalize_hostname(value: str) -> tuple[str, str]:
    """Return ``(a_label_form, display_form)`` for a hostname.

    Raises :class:`NormalizationError` if the value is not a syntactically
    valid multi-label domain name.
    """
    host = value.rstrip(".") if value.endswith(".") else value
    if not host:
        msg = "domain is empty"
        raise NormalizationError(msg)

    if host.isascii():
        canonical = host.lower()
        display = canonical
    else:
        try:
            canonical = idna.encode(host, uts46=True).decode("ascii")
        except idna.IDNAError as exc:
            msg = f"invalid internationalized domain name: {exc.__class__.__name__}"
            raise NormalizationError(msg) from exc
        try:
            display = idna.decode(canonical)
        except idna.IDNAError:  # pragma: no cover - encode/decode are symmetric
            display = canonical

    _validate_ascii_domain(canonical)
    return canonical, display


def _validate_ascii_domain(host: str) -> None:
    if len(host) > _MAX_DOMAIN_LENGTH:
        msg = f"domain exceeds {_MAX_DOMAIN_LENGTH} characters"
        raise NormalizationError(msg)
    labels = host.split(".")
    if len(labels) < 2:
        msg = "domain must have at least two labels"
        raise NormalizationError(msg)
    for label in labels:
        if not _ASCII_LABEL_RE.fullmatch(label) or label.endswith("-"):
            msg = "domain contains an invalid label"
            raise NormalizationError(msg)
    if not _TLD_RE.fullmatch(labels[-1]):
        msg = "domain has an invalid top-level label"
        raise NormalizationError(msg)


# --------------------------------------------------------------------------- #
# URLs
# --------------------------------------------------------------------------- #


def normalize_url(raw: str) -> IntelObject:
    """Normalize a URL.

    Normalized: the scheme (lowercased, undefanged), the host (lowercased,
    IDNA-encoded, undefanged) and a default port for the scheme, which is
    dropped. An empty path becomes ``/``.

    Deliberately **not** touched: path case, percent-encoding, query parameter
    order, query parameter presence, and the fragment. Those carry meaning for
    a suspicious URL and rewriting them would change the artifact.
    """
    candidate = _undefang_scheme(_prepare(raw))
    scheme, authority, tail = _split_url(candidate)
    if scheme not in ALLOWED_URL_SCHEMES:
        msg = f"URL scheme {scheme!r} is not supported"
        raise NormalizationError(msg)

    # Undefang the authority before handing the URL to urlsplit: bracketed text
    # is only ever defanging inside a host, whereas in a path or query it may be
    # part of the artifact itself.
    try:
        parts = urlsplit(f"{scheme}://{undefang(authority)}{tail}")
    except ValueError as exc:
        msg = "URL could not be parsed"
        raise NormalizationError(msg) from exc
    if not parts.netloc:
        msg = "URL is missing a host"
        raise NormalizationError(msg)

    userinfo, host, port = _split_authority(parts.netloc)
    canonical_host, display_host = _normalize_url_host(host)
    if port is not None and _DEFAULT_PORTS.get(scheme) == port:
        port = None

    path = parts.path or "/"
    canonical = urlunsplit(
        (scheme, _join_authority(userinfo, canonical_host, port), path, parts.query, parts.fragment)
    )
    display = urlunsplit(
        (scheme, _join_authority(userinfo, display_host, port), path, parts.query, parts.fragment)
    )
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.URL,
        canonical_value=canonical,
        display_value=display,
    )


def _split_url(candidate: str) -> tuple[str, str, str]:
    """Split a URL into ``(lowercased_scheme, authority, remainder)``."""
    scheme, separator, rest = candidate.partition("://")
    if not separator:
        msg = "URL is missing a scheme"
        raise NormalizationError(msg)
    if not scheme:
        msg = "URL is missing a scheme"
        raise NormalizationError(msg)
    cut = len(rest)
    for delimiter in "/?#":
        found = rest.find(delimiter)
        if found != -1:
            cut = min(cut, found)
    return scheme.lower(), rest[:cut], rest[cut:]


def _split_authority(netloc: str) -> tuple[str | None, str, int | None]:
    userinfo: str | None = None
    remainder = netloc
    if "@" in remainder:
        userinfo, _, remainder = remainder.rpartition("@")
    port: int | None = None
    if remainder.startswith("["):
        closing = remainder.find("]")
        if closing == -1:
            msg = "URL has an unterminated IPv6 host"
            raise NormalizationError(msg)
        host = remainder[: closing + 1]
        tail = remainder[closing + 1 :]
        if tail.startswith(":"):
            port = _parse_port(tail[1:])
        elif tail:
            msg = "URL authority is malformed"
            raise NormalizationError(msg)
    elif ":" in remainder:
        host, _, raw_port = remainder.rpartition(":")
        port = _parse_port(raw_port)
    else:
        host = remainder
    if not host:
        msg = "URL is missing a host"
        raise NormalizationError(msg)
    return userinfo, host, port


def _parse_port(raw_port: str) -> int:
    if not raw_port.isdigit():
        msg = "URL has an invalid port"
        raise NormalizationError(msg)
    port = int(raw_port)
    if not 1 <= port <= 65535:
        msg = "URL port is out of range"
        raise NormalizationError(msg)
    return port


def _normalize_url_host(host: str) -> tuple[str, str]:
    """Normalize a URL host, which may be an IP literal or a domain."""
    address = _parse_ip(host)
    if address is not None:
        literal = f"[{address}]" if address.version == 6 else str(address)
        return literal, literal
    return _normalize_hostname(undefang(host))


def _join_authority(userinfo: str | None, host: str, port: int | None) -> str:
    authority = host if port is None else f"{host}:{port}"
    return authority if userinfo is None else f"{userinfo}@{authority}"


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #


def normalize_observable(raw: str) -> NormalizationResult:
    """Detect and normalize any supported observable type.

    Detection order is hash, then URL (a scheme is unambiguous), then IP, then
    domain. Anything else is rejected rather than guessed at.
    """
    candidate = _prepare(raw)
    scheme_repaired = _undefang_scheme(candidate)

    if _HEX_RE.fullmatch(candidate) and len(candidate) in set(HASH_HEX_LENGTHS.values()):
        return NormalizationResult(original_input=raw, intel_object=normalize_file_hash(candidate))

    if "://" in scheme_repaired:
        return NormalizationResult(original_input=raw, intel_object=normalize_url(scheme_repaired))

    undefanged = undefang(candidate)
    if _parse_ip(undefanged) is not None:
        return NormalizationResult(original_input=raw, intel_object=normalize_ip(undefanged))

    if _HEX_RE.fullmatch(candidate):
        supported = sorted(HASH_HEX_LENGTHS.values())
        msg = f"looks like a hash but length {len(candidate)} is not one of {supported}"
        raise NormalizationError(msg, input_length=len(candidate))

    return NormalizationResult(original_input=raw, intel_object=normalize_domain(undefanged))

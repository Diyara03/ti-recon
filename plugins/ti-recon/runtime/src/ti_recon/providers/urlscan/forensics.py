"""Static forensic extraction from stored web artifacts (Task 8).

What a phishing page *is* — where its credential form posts, which scripts it
loads, which infrastructure it reaches for — read out of a DOM snapshot urlscan
already stored.

Static, and only static
-----------------------

Nothing here executes, renders, evaluates or interprets what it reads. There is
no ``eval``, no browser, no HTML renderer, no dynamic import and no shelling
out: the content is a hostile string that gets pattern-matched and then thrown
away. That is the whole security model of this module, and it is why extraction
is regex-and-slicing rather than anything cleverer.

Facts, never conclusions
------------------------

Everything extracted is recorded as an observation with no direction. "This page
has a password input" and "its form posts to another origin" are facts;
concluding *phishing* from them is engine interpretation, which belongs to the
assessment layer where it can be weighed against everything else. An adapter
that assigned a direction here would be turning its own inference into a
provider fact, which is exactly the layering the data model exists to prevent.

Secrets are detected, never kept
--------------------------------

A phishing kit's exfiltration code contains live credentials: a Telegram bot
token, a Mailgun key, a Discord webhook. Those are *someone's* secrets, they are
credential material, and storing them would turn an evidence record into a
credential store. So secret-bearing identifiers are recorded by **type and
count only** — the value is matched and immediately discarded, and never
logged, cached, attached to evidence, or written into a fingerprint.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Final
from urllib.parse import urlsplit

from pydantic import Field

from ti_recon.enums import EvidenceClass, EvidenceEffect
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.urlscan.normalizer import (
    NormalizationContext,
    ScanDocument,
    UrlscanNormalization,
    build_evidence,
)

__all__ = [
    "MAX_ITEMS_PER_CATEGORY",
    "MAX_SCAN_BYTES",
    "SECRET_BEARING_IDENTIFIERS",
    "TEXTUAL_MIME_TYPES",
    "ForensicFingerprints",
    "ForensicProfile",
    "analyze_dom",
    "analyze_script",
    "forensic_evidence",
    "select_response_bodies",
]

#: How much of an artifact is scanned. A DOM can be many megabytes of generated
#: markup; the parts that identify a kit are at the top, and an unbounded scan
#: over adversary-chosen input is a denial-of-service waiting to happen.
MAX_SCAN_BYTES: Final[int] = 512 * 1024

#: Bound on every extracted list. A page can contain ten thousand links.
MAX_ITEMS_PER_CATEGORY: Final[int] = 20

#: Longest single extracted value.
_MAX_VALUE_LENGTH: Final[int] = 2048

#: Identifier types whose *value* must never be retained.
#:
#: Each of these is live credential material belonging to somebody — usually to
#: the operator of the kit, occasionally to a victim. Detecting one is a real
#: finding ("this page exfiltrates over Telegram"); keeping it would make this
#: system a place credentials accumulate. Presence and count travel; the value
#: is discarded at the point of the match.
SECRET_BEARING_IDENTIFIERS: Final[dict[str, re.Pattern[str]]] = {
    "telegram.bot-token": re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,45}\b"),
    "telegram.bot-endpoint": re.compile(r"api\.telegram\.org/bot[A-Za-z0-9_:-]{10,60}"),
    "discord.webhook": re.compile(
        r"discord(?:app)?\.com/api/webhooks/\d{5,25}/[A-Za-z0-9_-]{20,80}"
    ),
    "google.api": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "json.jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
    "mailgun.api-key": re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
    "square.access-token": re.compile(r"\bsq0atp-[0-9A-Za-z_-]{22}\b"),
    "authorization.api": re.compile(
        r"(?i)authorization\s*[:=]\s*[\"']?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{10,}"
    ),
}

#: Extraction patterns. Each is anchored, bounded and free of nested
#: quantifiers, so no input can make one of them expensive to evaluate.
_FORM_ACTION_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)<form\b[^>]{0,2000}?\baction\s*=\s*[\"']([^\"'>]{1,2048})[\"']"
)
_SCRIPT_SRC_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)<script\b[^>]{0,2000}?\bsrc\s*=\s*[\"']([^\"'>]{1,2048})[\"']"
)
_IFRAME_SRC_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)<iframe\b[^>]{0,2000}?\bsrc\s*=\s*[\"']([^\"'>]{1,2048})[\"']"
)
_INPUT_TAG_RE: Final[re.Pattern[str]] = re.compile(r"(?is)<input\b[^>]{0,2000}>")
_INPUT_NAME_RE: Final[re.Pattern[str]] = re.compile(r"(?is)\bname\s*=\s*[\"']([^\"'>]{1,128})[\"']")
_INPUT_TYPE_RE: Final[re.Pattern[str]] = re.compile(r"(?is)\btype\s*=\s*[\"']([^\"'>]{1,32})[\"']")
_META_REFRESH_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)<meta\b[^>]{0,500}?http-equiv\s*=\s*[\"']refresh[\"'][^>]{0,500}?"
    r"url\s*=\s*([^\"'>]{1,2048})[\"']"
)
_TITLE_RE: Final[re.Pattern[str]] = re.compile(r"(?is)<title\b[^>]{0,200}>(.{0,300}?)</title>")
_TAG_RE: Final[re.Pattern[str]] = re.compile(r"(?i)<\s*([a-z][a-z0-9]{0,20})\b")
_ABSOLUTE_URL_RE: Final[re.Pattern[str]] = re.compile(r"https?://[^\s\"'<>()]{1,2048}")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{64}$")

#: Response bodies worth reading. Everything else a page serves is bytes whose
#: content tells an analyst nothing that its digest does not.
TEXTUAL_MIME_TYPES: Final[frozenset[str]] = frozenset(
    {
        "text/html",
        "text/plain",
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
        "application/json",
        "text/css",
    }
)


class ForensicFingerprints(FrozenTiReconModel):
    """Digests that let one page be recognized on another domain.

    A kit deployed a hundred times has the same structure, the same form target
    and the same script set every time. These digests are how the ninety-ninth
    deployment is recognized as the same thing as the first — which is the point
    of forensic extraction, and the reason it is worth its cost.

    Every digest is computed from *structure*, never from content that could
    carry a secret.
    """

    #: The sequence of element names, hashed. Stable across changed text and
    #: regenerated identifiers; changes when the page is rebuilt.
    dom_structure: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    #: The set of form targets, hashed. Two pages posting to the same endpoint
    #: are the same operation even when nothing else matches.
    form_targets: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    #: The set of script sources, hashed.
    script_set: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @property
    def is_empty(self) -> bool:
        return not (self.dom_structure or self.form_targets or self.script_set)


class ForensicProfile(FrozenTiReconModel):
    """What static analysis of one stored artifact found.

    Facts only. Nothing here is a judgement, and nothing here is a value that
    could be a credential.
    """

    form_actions: tuple[str, ...] = ()
    #: Form targets on a different origin from the page itself. Recorded as its
    #: own field because "where the credentials go" is the question an analyst
    #: asks, not because this module has decided what it means.
    cross_origin_form_actions: tuple[str, ...] = ()
    script_sources: tuple[str, ...] = ()
    iframe_sources: tuple[str, ...] = ()
    input_names: tuple[str, ...] = ()
    #: Whether any input is masked — a ``type="password"`` field. Named for what
    #: the browser does rather than for what it collects, because an attribute
    #: key containing "password" is refused by the evidence layer's guard
    #: against credential material, and that guard is worth more than the name.
    has_masked_input: bool = False
    meta_refresh_targets: tuple[str, ...] = ()
    referenced_hosts: tuple[str, ...] = ()
    title: str | None = Field(default=None, max_length=300)
    #: Types of secret-bearing identifier found, with how many. Never a value.
    sensitive_identifier_counts: dict[str, int] = Field(default_factory=dict)
    fingerprints: ForensicFingerprints = ForensicFingerprints()
    #: Whether the artifact was longer than :data:`MAX_SCAN_BYTES`, so a caller
    #: knows an absent finding may simply be past the horizon.
    scan_truncated: bool = False

    @property
    def is_empty(self) -> bool:
        return not (
            self.form_actions
            or self.script_sources
            or self.iframe_sources
            or self.input_names
            or self.meta_refresh_targets
            or self.referenced_hosts
            or self.title
            or self.sensitive_identifier_counts
        )

    @property
    def sensitive_identifier_types(self) -> tuple[str, ...]:
        return tuple(sorted(self.sensitive_identifier_counts))


def analyze_dom(content: bytes, *, page_url: str | None = None) -> ForensicProfile:
    """Extract a bounded forensic profile from a stored DOM snapshot.

    ``page_url`` is used only to decide which form targets are cross-origin. It
    is never fetched — nothing in TI Recon follows a URL found in page content,
    which is the whole reason suspicious URLs are investigated through a
    provider in the first place.
    """
    text, truncated = _decode(content)
    if not text:
        return ForensicProfile(scan_truncated=truncated)

    page_host = _host_of(page_url) if page_url else None
    form_actions = _bounded(_FORM_ACTION_RE.findall(text))
    script_sources = _bounded(_SCRIPT_SRC_RE.findall(text))
    iframe_sources = _bounded(_IFRAME_SRC_RE.findall(text))
    input_names, has_password = _inputs(text)

    return ForensicProfile(
        form_actions=form_actions,
        cross_origin_form_actions=_cross_origin(form_actions, page_host),
        script_sources=script_sources,
        iframe_sources=iframe_sources,
        input_names=input_names,
        has_masked_input=has_password,
        meta_refresh_targets=_bounded(_META_REFRESH_RE.findall(text)),
        referenced_hosts=_referenced_hosts(text),
        title=_title(text),
        sensitive_identifier_counts=_secret_indicators(text),
        fingerprints=_fingerprints(text, form_actions, script_sources),
        scan_truncated=truncated,
    )


def analyze_script(content: bytes) -> ForensicProfile:
    """Extract what matters from a stored response body.

    Narrower than :func:`analyze_dom` on purpose. A script body has no forms and
    no inputs; what it has is the infrastructure it talks to and, in a phishing
    kit, the credentials it talks to it with. Both of those are extracted, and
    only one of them is kept.

    No fingerprints are computed: the body is already content-addressed by its
    own SHA-256, which is a better identity than anything derived here.
    """
    text, truncated = _decode(content)
    if not text:
        return ForensicProfile(scan_truncated=truncated)
    return ForensicProfile(
        referenced_hosts=_referenced_hosts(text),
        sensitive_identifier_counts=_secret_indicators(text),
        scan_truncated=truncated,
    )


def select_response_bodies(document: ScanDocument, limit: int) -> tuple[str, ...]:
    """Which stored bodies are worth retrieving, newest-page-first.

    Only textual resources, and only up to ``limit`` of them. A page serves
    hundreds of images and fonts whose bytes tell an analyst nothing; the
    scripts and documents are where a kit's logic and its exfiltration endpoint
    live.
    """
    if limit < 1:
        return ()
    requests = document.block("data").get("requests")
    if not isinstance(requests, list):
        return ()
    digests: list[str] = []
    for entry in requests:
        digest = _textual_body_digest(entry)
        if digest is None or digest in digests:
            continue
        digests.append(digest)
        if len(digests) >= limit:
            break
    return tuple(digests)


def _textual_body_digest(entry: object) -> str | None:
    """The SHA-256 of one response body, if that body was textual."""
    if not isinstance(entry, Mapping):
        return None
    response = entry.get("response")
    if not isinstance(response, Mapping):
        return None
    inner = response.get("response")
    if not isinstance(inner, Mapping):
        return None
    mime = inner.get("mimeType")
    if not isinstance(mime, str) or mime.split(";", 1)[0].strip().lower() not in (
        TEXTUAL_MIME_TYPES
    ):
        return None
    digest = inner.get("hash")
    if not isinstance(digest, str) or not _SHA256_RE.match(digest.strip()):
        return None
    return digest.strip().lower()


def forensic_evidence(
    context: NormalizationContext,
    profile: ForensicProfile,
    *,
    artifact_id: str | None = None,
    claim_type: str = "urlscan_page_forensics",
) -> UrlscanNormalization:
    """Record a forensic profile as observations.

    Two pieces at most: what the page contains, and what identifies it. Both are
    ``CONTEXT_ONLY`` — extraction produces facts, and deciding what those facts
    mean is the assessment layer's job, not an adapter's.

    A profile that found nothing still produces evidence when the scan was
    truncated. "We looked and found nothing" and "we stopped looking early" are
    different statements, and only one of them supports concluding the page is
    plain.
    """
    if profile.is_empty and profile.fingerprints.is_empty and not profile.scan_truncated:
        return UrlscanNormalization()

    results: list[UrlscanNormalization] = []
    attributes: dict[str, object] = {}
    if artifact_id:
        attributes["artifact_id"] = artifact_id
    for name, value in (
        ("form_actions", profile.form_actions),
        ("cross_origin_form_actions", profile.cross_origin_form_actions),
        ("script_sources", profile.script_sources),
        ("iframe_sources", profile.iframe_sources),
        ("input_names", profile.input_names),
        ("meta_refresh_targets", profile.meta_refresh_targets),
        ("referenced_hosts", profile.referenced_hosts),
    ):
        if value:
            attributes[name] = list(value)
    if profile.title:
        attributes["title"] = profile.title
    attributes["has_masked_input"] = profile.has_masked_input
    if profile.scan_truncated:
        attributes["scan_truncated"] = True
    if profile.sensitive_identifier_counts:
        # Types and counts. The matched values were discarded where they were
        # found and exist nowhere in this process.
        attributes["sensitive_identifier_types"] = list(profile.sensitive_identifier_types)
        attributes["sensitive_identifier_counts"] = dict(profile.sensitive_identifier_counts)

    if len(attributes) > 1 or profile.scan_truncated:
        results.append(
            UrlscanNormalization(
                evidence=(
                    build_evidence(
                        context,
                        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
                        claim_type=claim_type,
                        effect=EvidenceEffect.CONTEXT_ONLY,
                        attributes=attributes,
                    ),
                )
            )
        )

    if not profile.fingerprints.is_empty:
        fingerprint_attributes: dict[str, object] = {
            name: value
            for name, value in profile.fingerprints.model_dump().items()
            if value is not None
        }
        if artifact_id:
            fingerprint_attributes["artifact_id"] = artifact_id
        results.append(
            UrlscanNormalization(
                evidence=(
                    build_evidence(
                        context,
                        evidence_class=EvidenceClass.CONTEXT,
                        claim_type="urlscan_page_fingerprints",
                        effect=EvidenceEffect.CONTEXT_ONLY,
                        attributes=fingerprint_attributes,
                    ),
                )
            )
        )

    merged = UrlscanNormalization()
    for result in results:
        merged = merged.merge(result)
    return merged


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


def _decode(content: bytes) -> tuple[str, bool]:
    """Decode a bounded prefix of an artifact into text.

    Undecodable bytes are replaced rather than raising: a kit is not obliged to
    serve valid UTF-8, and refusing to look at malformed markup would be an easy
    way to hide from analysis.
    """
    truncated = len(content) > MAX_SCAN_BYTES
    return content[:MAX_SCAN_BYTES].decode("utf-8", errors="replace"), truncated


def _bounded(values: list[str]) -> tuple[str, ...]:
    """De-duplicate, bound and clean a list of extracted values."""
    out: list[str] = []
    for value in values:
        cleaned = _clean(value)
        if cleaned is None or cleaned in out:
            continue
        out.append(cleaned)
        if len(out) >= MAX_ITEMS_PER_CATEGORY:
            break
    return tuple(out)


def _clean(value: str) -> str | None:
    cleaned = "".join(
        character
        for character in value.strip()
        if ord(character) >= 0x20 and ord(character) != 0x7F
    )[:_MAX_VALUE_LENGTH]
    return cleaned or None


def _inputs(text: str) -> tuple[tuple[str, ...], bool]:
    """Field names, and whether any of them takes a password."""
    names: list[str] = []
    has_password = False
    for tag in _INPUT_TAG_RE.findall(text)[: MAX_ITEMS_PER_CATEGORY * 5]:
        type_match = _INPUT_TYPE_RE.search(tag)
        if type_match and type_match.group(1).strip().lower() == "password":
            has_password = True
        name_match = _INPUT_NAME_RE.search(tag)
        if name_match is None:
            continue
        cleaned = _clean(name_match.group(1))
        if cleaned is not None and cleaned not in names:
            names.append(cleaned)
    return tuple(names[:MAX_ITEMS_PER_CATEGORY]), has_password


def _cross_origin(actions: tuple[str, ...], page_host: str | None) -> tuple[str, ...]:
    """Form targets that leave the page's own origin.

    A relative target stays on the page, so it is not cross-origin. Without a
    page URL to compare against, every absolute target is reported: saying "we
    could not tell" by omitting them would hide the interesting case.
    """
    out: list[str] = []
    for action in actions:
        host = _host_of(action)
        if host is None:
            continue
        if page_host is not None and host == page_host:
            continue
        out.append(action)
    return tuple(out)


def _referenced_hosts(text: str) -> tuple[str, ...]:
    """Every host an absolute URL in the artifact points at."""
    hosts: list[str] = []
    for url in _ABSOLUTE_URL_RE.findall(text):
        host = _host_of(url)
        if host is None or host in hosts:
            continue
        hosts.append(host)
        if len(hosts) >= MAX_ITEMS_PER_CATEGORY:
            break
    return tuple(hosts)


def _host_of(value: str) -> str | None:
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    return parts.hostname.lower()[:253]


def _title(text: str) -> str | None:
    match = _TITLE_RE.search(text)
    if match is None:
        return None
    cleaned = _clean(match.group(1))
    return cleaned[:300] if cleaned else None


def _secret_indicators(text: str) -> dict[str, int]:
    """Count secret-bearing identifiers by type, keeping no value.

    ``len(matches)`` is the only thing taken from the match objects; the matched
    strings are never bound to a name, never returned and never logged.
    """
    counts: dict[str, int] = {}
    for name, pattern in SECRET_BEARING_IDENTIFIERS.items():
        found = len(pattern.findall(text))
        if found:
            counts[name] = min(found, 1000)
    return counts


def _fingerprints(
    text: str, form_actions: tuple[str, ...], script_sources: tuple[str, ...]
) -> ForensicFingerprints:
    """Digests over structure only — never over anything that could be a secret."""
    tags = [tag.lower() for tag in _TAG_RE.findall(text)]
    return ForensicFingerprints(
        dom_structure=_digest(">".join(tags)) if tags else None,
        form_targets=_digest("\n".join(sorted(form_actions))) if form_actions else None,
        script_set=_digest("\n".join(sorted(script_sources))) if script_sources else None,
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()

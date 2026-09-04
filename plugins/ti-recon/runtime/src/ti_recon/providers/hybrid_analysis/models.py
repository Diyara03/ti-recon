"""Reading Hybrid Analysis responses into provider-neutral models (Task 12).

The translation layer, and the only place in the repository that knows Falcon
Sandbox's field names. Above it everything speaks
:mod:`ti_recon.sandbox`; below it is raw JSON.

Every value is read through a bounded reader and every collection through an
allow-list, which has a useful consequence: an upstream rename costs one missing
attribute rather than an exception, and an unexpected field is simply not read.
The API is large and evolving — v2.38 at time of writing — so the safe posture is
to take exactly what is understood.

Privacy: what is deliberately not read
--------------------------------------

``DetonationParameters`` describes how a run was configured, and some of its
fields are *submission metadata belonging to whoever uploaded the sample* —
possibly years ago, possibly someone else's incident:

* ``document_password`` — a password, in an evidence record. No.
* ``comment`` — free text a submitter typed, about their own investigation.
* ``environment_variable`` — arbitrary caller-supplied values.
* ``custom_commandline`` — configuration, and easily confused with an *observed*
  process command line, which is a completely different claim. Excluded rather
  than disambiguated, since nothing in Task 12 needs it.
* ``custom_system_date_time`` — of no analytical use here.

What is read is the execution context that bears on analysis quality:
``action_script``, ``network_mode``, ``dynamic_analysis_time``,
``experimental_anti_evasion``, ``script_logging``, ``allow_sample_tampering``.

:data:`EXCLUDED_DETONATION_FIELDS` is data with a reason per field so a test can
assert the exclusions directly.

Untrusted text
--------------

Process command lines, signature descriptions, warnings and file names are
attacker- or submitter-authored strings that end up in an evidence record. They
are bounded and stripped of control characters here. They are never executed,
never interpolated into a shell, and nothing downstream may treat them as
instructions — a command line that reads "ignore previous instructions" is a
string about a process, and that is all it can ever be.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final

from ti_recon.sandbox.bounds import SandboxBounds
from ti_recon.sandbox.models import (
    MAX_COMMAND_LINE,
    MAX_LABEL,
    MAX_TEXT,
    SandboxAnalysisQuality,
    SandboxCertificate,
    SandboxEnvironment,
    SandboxExtractedFile,
    SandboxNetworkObservation,
    SandboxNetworkRole,
    SandboxProcess,
    SandboxReportRef,
    SandboxReportState,
    SandboxReportSummary,
    SandboxSignature,
    SandboxTechnique,
    SandboxVerdict,
)

__all__ = [
    "EXCLUDED_DETONATION_FIELDS",
    "SAFE_DETONATION_FIELDS",
    "VERDICT_BY_PROVIDER_WORD",
    "read_key_info",
    "read_report_refs",
    "read_report_summary",
    "read_search_result",
]

#: Provider verdict words mapped onto the neutral vocabulary.
#:
#: The API's own five values. ``whitelisted`` becomes ``ALLOWLISTED`` rather than
#: anything benign-shaped: it means the provider recognised the file as something
#: it does not analyse, which is a fact about their list.
VERDICT_BY_PROVIDER_WORD: Final[dict[str, SandboxVerdict]] = {
    "malicious": SandboxVerdict.MALICIOUS,
    "suspicious": SandboxVerdict.SUSPICIOUS,
    "no specific threat": SandboxVerdict.NO_SPECIFIC_THREAT,
    "no verdict": SandboxVerdict.NO_VERDICT,
    "whitelisted": SandboxVerdict.ALLOWLISTED,
    "allowlisted": SandboxVerdict.ALLOWLISTED,
}

#: Report state words mapped onto the neutral vocabulary.
_STATE_BY_PROVIDER_WORD: Final[dict[str, SandboxReportState]] = {
    "SUCCESS": SandboxReportState.SUCCESS,
    "PARTIAL_SUCCESS": SandboxReportState.PARTIAL_SUCCESS,
    "ERROR": SandboxReportState.ERROR,
    "IN_QUEUE": SandboxReportState.IN_QUEUE,
    "IN_PROGRESS": SandboxReportState.IN_PROGRESS,
}

#: Detonation-parameter fields that describe the run and are safe to keep.
SAFE_DETONATION_FIELDS: Final[tuple[str, ...]] = (
    "action_script",
    "network_mode",
    "dynamic_analysis_time",
    "experimental_anti_evasion",
    "script_logging",
    "allow_sample_tampering",
)

#: Detonation-parameter fields never read, and why. Kept as data so a test can
#: assert the list rather than trust a comment.
EXCLUDED_DETONATION_FIELDS: Final[dict[str, str]] = {
    "document_password": "a password belonging to whoever submitted the sample",
    "comment": "free text a submitter wrote about their own investigation",
    "environment_variable": "arbitrary caller-supplied values",
    "custom_commandline": (
        "run configuration, easily confused with an observed process command line"
    ),
    "custom_system_date_time": "no analytical use, and submitter-controlled",
}

_HEX: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]+\Z")
_ATTACK_ID: Final[re.Pattern[str]] = re.compile(r"\AT[0-9]{4}(?:\.[0-9]{3})?\Z")
_CAPEC_ID: Final[re.Pattern[str]] = re.compile(r"\A(?:CAPEC-)?[0-9]{1,5}\Z")


# --------------------------------------------------------------------------- #
# Bounded readers
# --------------------------------------------------------------------------- #


def _text(value: Any, limit: int = MAX_LABEL) -> str | None:
    """A bounded, control-character-free string, or ``None``.

    Control characters are stripped rather than escaped: nothing downstream has a
    use for them, and a stored newline is how provider text starts looking like
    structure to whatever renders it later.
    """
    if not isinstance(value, str):
        return None
    cleaned = "".join(
        character
        for character in value.strip()
        if ord(character) >= 0x20 and ord(character) != 0x7F
    )[:limit]
    return cleaned or None


def _count(value: Any) -> int | None:
    """A non-negative integer, or ``None``. Numeric strings accepted."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        return int(value) if value >= 0 else None
    if isinstance(value, str):
        try:
            parsed = int(value.strip())
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def _flag(value: Any) -> bool | None:
    """A boolean, or ``None``. Never a guess: an unrecognized value stays unknown."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def _digest(value: Any, length: int) -> str | None:
    """A lowercase hex digest of exactly ``length``, or ``None``.

    Shape-checked because a digest becomes an object identity and a pivot key.
    """
    candidate = _text(value, 200)
    if candidate is None:
        return None
    lowered = candidate.lower()
    return lowered if len(lowered) == length and _HEX.fullmatch(lowered) else None


def _timestamp(value: Any) -> datetime | None:
    """An ISO-8601 instant as timezone-aware UTC, or ``None``.

    A naive value is read as UTC rather than as local time: the provider is not
    reporting our timezone.
    """
    candidate = _text(value, 64)
    if candidate is None:
        return None
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _string_list(value: Any, limit: int, item_limit: int = MAX_LABEL) -> tuple[str, ...]:
    """A bounded, de-duplicated tuple of bounded strings."""
    if isinstance(value, str):
        single = _text(value, item_limit)
        return (single,) if single else ()
    if not isinstance(value, Sequence) or isinstance(value, bytes):
        return ()
    kept: list[str] = []
    for entry in value:
        cleaned = _text(entry, item_limit)
        if cleaned is None or cleaned in kept:
            continue
        kept.append(cleaned)
        if len(kept) >= limit:
            break
    return tuple(kept)


def _mappings(value: Any, limit: int) -> list[Mapping[str, Any]]:
    """A bounded list of mappings, skipping anything else."""
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return []
    kept: list[Mapping[str, Any]] = []
    for entry in value:
        if isinstance(entry, Mapping):
            kept.append(entry)
        if len(kept) >= limit:
            break
    return kept


def _verdict(value: Any) -> tuple[SandboxVerdict, str | None]:
    """``(neutral verdict, provider's own word)``.

    The raw word is kept because the mapping is lossy by design: ``suspicious``
    and ``malicious`` both point the same way, and an analyst may want to know
    which was said.
    """
    raw = _text(value, 64)
    if raw is None:
        return SandboxVerdict.UNKNOWN, None
    return VERDICT_BY_PROVIDER_WORD.get(raw.strip().lower(), SandboxVerdict.UNKNOWN), raw


def _state(value: Any) -> SandboxReportState:
    raw = _text(value, 64)
    if raw is None:
        return SandboxReportState.UNKNOWN
    return _STATE_BY_PROVIDER_WORD.get(raw.strip().upper(), SandboxReportState.UNKNOWN)


def _environment(payload: Mapping[str, Any]) -> SandboxEnvironment:
    identifier = payload.get("environment_id")
    return SandboxEnvironment(
        environment_id=_text(identifier, 64)
        or (str(identifier) if isinstance(identifier, int) else None),
        description=_text(payload.get("environment_description"), MAX_LABEL),
    )


# --------------------------------------------------------------------------- #
# Hash search
# --------------------------------------------------------------------------- #


def read_search_result(payload: Any) -> tuple[str | None, tuple[SandboxReportRef, ...]]:
    """``(canonical sha256, report index)`` from a hash search.

    The API has returned both a list of per-sample records and a single object
    over its life, so both shapes are accepted: refusing to read a document
    because the envelope changed would lose real coverage over a formatting
    difference.
    """
    records = payload if isinstance(payload, list) else [payload]
    sha256: str | None = None
    refs: list[SandboxReportRef] = []
    seen: set[str] = set()

    for record in records:
        if not isinstance(record, Mapping):
            continue
        sha256 = sha256 or _digest(record.get("sha256"), 64)
        # A search record is itself a report in the flat form the API returns.
        for ref in read_report_refs(record):
            if ref.report_id in seen:
                continue
            seen.add(ref.report_id)
            refs.append(ref)
    return sha256, tuple(refs)


def read_report_refs(record: Mapping[str, Any]) -> tuple[SandboxReportRef, ...]:
    """Report references from one search record.

    Handles both the nested ``reports`` array and the flat form where the record
    *is* the report.
    """
    nested = _mappings(record.get("reports"), 200)
    if nested:
        return tuple(ref for ref in (_report_ref(item) for item in nested) if ref is not None)
    single = _report_ref(record)
    return () if single is None else (single,)


def _report_ref(payload: Mapping[str, Any]) -> SandboxReportRef | None:
    identifier = (
        _text(payload.get("report_id"), 128)
        or _text(payload.get("id"), 128)
        or _text(payload.get("job_id"), 128)
    )
    if identifier is None:
        return None
    verdict, raw_verdict = _verdict(payload.get("verdict"))
    return SandboxReportRef(
        report_id=identifier,
        environment=_environment(payload),
        state=_state(payload.get("state")),
        verdict=verdict,
        raw_verdict=raw_verdict,
        error_type=_text(payload.get("error_type"), MAX_LABEL),
        error_origin=_text(payload.get("error_origin"), MAX_LABEL),
    )


# --------------------------------------------------------------------------- #
# Report summary
# --------------------------------------------------------------------------- #


def read_report_summary(
    payload: Any, *, report_id: str, bounds: SandboxBounds
) -> SandboxReportSummary | None:
    """One report's summary, bounded per ``bounds``.

    ``None`` when the body is not a JSON object: a shape change should cost this
    report's detail, not the lookup.
    """
    if not isinstance(payload, Mapping):
        return None
    verdict, raw_verdict = _verdict(payload.get("verdict"))
    truncated: dict[str, bool] = {}

    signatures = _read_signatures(payload.get("signatures"), bounds.signatures, truncated)
    techniques = _read_techniques(payload.get("mitre_attcks"), bounds.techniques, truncated)
    processes = _read_processes(payload.get("processes"), bounds.processes, truncated)
    network = _read_network(payload, bounds.network, truncated)
    extracted = _read_extracted_files(
        payload.get("extracted_files"), bounds.extracted_files, truncated
    )
    certificates = _read_certificates(payload.get("certificates"), bounds.certificates, truncated)

    tags = _string_list(payload.get("classification_tags"), bounds.tags)
    if not tags:
        tags = _string_list(payload.get("tags"), bounds.tags)

    return SandboxReportSummary(
        report_id=report_id,
        environment=_environment(payload),
        verdict=verdict,
        raw_verdict=raw_verdict,
        quality=_read_quality(payload, bounds),
        threat_score=_bounded_score(payload.get("threat_score")),
        threat_level=_count(payload.get("threat_level")),
        family_label=_text(payload.get("vx_family"), MAX_LABEL),
        tags=tags,
        signatures=signatures,
        techniques=techniques,
        processes=processes,
        network=network,
        extracted_files=extracted,
        certificates=certificates,
        hashes=_read_hashes(payload),
        truncated=truncated,
    )


def _bounded_score(value: Any) -> int | None:
    """A threat score inside 0-100, or ``None``.

    Clamped rather than rejected at the top end: the model bounds it, and a
    provider reporting 120 means "very bad" rather than "invalid".
    """
    parsed = _count(value)
    return None if parsed is None else min(parsed, 100)


def _read_hashes(payload: Mapping[str, Any]) -> dict[str, str]:
    """Alternate digests for the analysed sample.

    Kept so a lookup by MD5 learns the SHA-256 the provider indexed it under.
    """
    found: dict[str, str] = {}
    for name, length in (("MD5", 32), ("SHA-1", 40), ("SHA-256", 64)):
        digest = _digest(payload.get(name.replace("-", "").lower()), length)
        if digest is not None:
            found[name] = digest
    return found


def _read_quality(payload: Mapping[str, Any], bounds: SandboxBounds) -> SandboxAnalysisQuality:
    """The execution context, from the report and its detonation parameters.

    Only the safe detonation fields — see :data:`EXCLUDED_DETONATION_FIELDS`.
    """
    parameters = payload.get("detonation_parameters")
    detonation: Mapping[str, Any] = parameters if isinstance(parameters, Mapping) else {}
    return SandboxAnalysisQuality(
        state=_state(payload.get("state")),
        analysis_started_at=_timestamp(payload.get("analysis_start_time")),
        total_processes=_count(payload.get("total_processes")),
        total_network_connections=_count(payload.get("total_network_connections")),
        total_signatures=_count(payload.get("total_signatures")),
        runtime_seconds=_count(detonation.get("dynamic_analysis_time")),
        network_mode=_text(detonation.get("network_mode") or payload.get("network_mode"), 64),
        action_script=_text(detonation.get("action_script"), 64),
        anti_evasion=_flag(detonation.get("experimental_anti_evasion")),
        script_logging=_flag(detonation.get("script_logging")),
        sample_tampering_allowed=_flag(detonation.get("allow_sample_tampering")),
        warnings=_string_list(payload.get("warnings"), bounds.warnings, MAX_TEXT),
    )


def _read_signatures(
    value: Any, limit: int, truncated: dict[str, bool]
) -> tuple[SandboxSignature, ...]:
    if limit == 0:
        return ()
    entries = _mappings(value, limit)
    total = len(value) if isinstance(value, Sequence) and not isinstance(value, str) else 0
    truncated["signatures"] = total > len(entries)
    return tuple(
        SandboxSignature(
            name=_text(item.get("name"), MAX_LABEL),
            category=_text(item.get("category"), MAX_LABEL),
            description=_text(item.get("description"), MAX_TEXT),
            threat_level=_count(item.get("threat_level")),
            threat_level_label=_text(item.get("threat_level_human"), 64),
            relevance=_count(item.get("relevance")),
            attack_id=_attack_id(item.get("attck_id")),
            capec_id=_capec_id(item.get("capec_id")),
        )
        for item in entries
    )


def _read_techniques(
    value: Any, limit: int, truncated: dict[str, bool]
) -> tuple[SandboxTechnique, ...]:
    if limit == 0:
        return ()
    entries = _mappings(value, limit)
    total = len(value) if isinstance(value, Sequence) and not isinstance(value, str) else 0
    truncated["techniques"] = total > len(entries)
    return tuple(
        SandboxTechnique(
            technique=_text(item.get("technique"), MAX_LABEL),
            tactic=_text(item.get("tactic"), MAX_LABEL),
            attack_id=_attack_id(item.get("attck_id")),
            parent_attack_id=_parent_attack_id(item.get("parent")),
            malicious_identifiers=_count(item.get("malicious_identifiers_count")),
            suspicious_identifiers=_count(item.get("suspicious_identifiers_count")),
            informative_identifiers=_count(item.get("informative_identifiers_count")),
        )
        for item in entries
    )


def _parent_attack_id(value: Any) -> str | None:
    """A parent technique id, from either a nested object or a bare string."""
    if isinstance(value, Mapping):
        return _attack_id(value.get("attck_id"))
    return _attack_id(value)


def _attack_id(value: Any) -> str | None:
    """A shape-checked ATT&CK technique id, or ``None``.

    Validated rather than passed through: an id is a lookup key elsewhere, and a
    malformed one is worse than an absent one.
    """
    candidate = _text(value, 32)
    if candidate is None:
        return None
    upper = candidate.strip().upper()
    return upper if _ATTACK_ID.fullmatch(upper) else None


def _capec_id(value: Any) -> str | None:
    candidate = _text(value, 32)
    if candidate is None:
        return None
    upper = candidate.strip().upper()
    return upper if _CAPEC_ID.fullmatch(upper) else None


def _read_processes(
    value: Any, limit: int, truncated: dict[str, bool]
) -> tuple[SandboxProcess, ...]:
    """Bounded process observations.

    ``icon`` is never read — it is base64 image data, which has no analytical
    value and would dominate the size of an evidence record.
    """
    if limit == 0:
        return ()
    entries = _mappings(value, limit)
    total = len(value) if isinstance(value, Sequence) and not isinstance(value, str) else 0
    truncated["processes"] = total > len(entries)
    return tuple(
        SandboxProcess(
            name=_text(item.get("name"), MAX_LABEL),
            normalized_path=_text(item.get("normalized_path"), MAX_TEXT),
            command_line=_text(item.get("command_line"), MAX_COMMAND_LINE),
            sha256=_digest(item.get("sha256"), 64),
            process_id=_text(item.get("uid"), 64),
            parent_process_id=_text(item.get("parentuid"), 64),
        )
        for item in entries
    )


def _read_network(
    payload: Mapping[str, Any], limit: int, truncated: dict[str, bool]
) -> tuple[SandboxNetworkObservation, ...]:
    """Domains and hosts observed during the run.

    ``compromised_hosts`` keeps the provider's stronger classification without
    reinterpretation, and a value's kind is decided by *parsing* it rather than
    by trusting which list it arrived in — a provider putting an address in the
    domain array should not create a domain object.
    """
    if limit == 0:
        return ()
    observations: list[SandboxNetworkObservation] = []
    seen: set[str] = set()
    total = 0

    for field, role in (
        ("domains", SandboxNetworkRole.CONTACTED),
        ("hosts", SandboxNetworkRole.CONTACTED),
        ("compromised_hosts", SandboxNetworkRole.COMPROMISED_HOST),
    ):
        raw = payload.get(field)
        values = _string_list(raw, limit * 4, MAX_TEXT)
        total += len(values)
        for value in values:
            kind = _network_kind(value)
            if kind is None or value in seen:
                continue
            seen.add(value)
            if len(observations) >= limit:
                continue
            observations.append(SandboxNetworkObservation(value=value, kind=kind, role=role))
    truncated["network"] = total > len(observations)
    return tuple(observations)


def _network_kind(value: str) -> str | None:
    """``"ipv4"``, ``"ipv6"``, ``"domain"`` or ``None``, decided by parsing."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        candidate = value.strip().lower().rstrip(".")
        if not candidate or " " in candidate or "/" in candidate or "." not in candidate:
            return None
        return "domain"
    return "ipv6" if address.version == 6 else "ipv4"


def _read_extracted_files(
    value: Any, limit: int, truncated: dict[str, bool]
) -> tuple[SandboxExtractedFile, ...]:
    if limit == 0:
        return ()
    entries = _mappings(value, limit)
    total = len(value) if isinstance(value, Sequence) and not isinstance(value, str) else 0
    truncated["extracted_files"] = total > len(entries)
    return tuple(
        SandboxExtractedFile(
            name=_text(item.get("name"), MAX_LABEL),
            file_path=_text(item.get("file_path"), MAX_TEXT),
            size_bytes=_count(item.get("file_size")),
            md5=_digest(item.get("md5"), 32),
            sha1=_digest(item.get("sha1"), 40),
            sha256=_digest(item.get("sha256"), 64),
            type_tags=_string_list(item.get("type_tags"), 10),
            threat_level=_count(item.get("threat_level")),
            av_label=_text(item.get("av_label"), MAX_LABEL),
            av_matched=_count(item.get("av_matched")),
            av_total=_count(item.get("av_total")),
        )
        for item in entries
    )


def _read_certificates(
    value: Any, limit: int, truncated: dict[str, bool]
) -> tuple[SandboxCertificate, ...]:
    """Bounded certificate context.

    The ``md5``/``sha1`` fields on a certificate are *fingerprints*, and are
    modelled as such: a certificate fingerprint is not a file hash, however
    identical their shape.
    """
    if limit == 0:
        return ()
    entries = _mappings(value, limit)
    total = len(value) if isinstance(value, Sequence) and not isinstance(value, str) else 0
    truncated["certificates"] = total > len(entries)
    return tuple(
        SandboxCertificate(
            owner=_text(item.get("owner"), MAX_LABEL),
            issuer=_text(item.get("issuer"), MAX_LABEL),
            serial_number=_text(item.get("serial_number"), 128),
            md5_fingerprint=_digest(item.get("md5"), 32),
            sha1_fingerprint=_digest(item.get("sha1"), 40),
            valid_from=_timestamp(item.get("valid_from")),
            valid_until=_timestamp(item.get("valid_until")),
        )
        for item in entries
    )


# --------------------------------------------------------------------------- #
# Key info
# --------------------------------------------------------------------------- #


def read_key_info(payload: Any) -> dict[str, Any]:
    """Safe fields from ``/key/current``.

    **The response contains the API key itself**, in a field called ``api_key``.
    It is never read, so it can never be stored, logged, cached or attached to an
    error — and because this reader returns an allow-listed dictionary rather than
    filtering a copy, the key is not merely removed, it is never picked up.

    ``user`` is ignored for the same reason it would be tempting: it identifies a
    person, and nothing here needs to know who owns the key.
    """
    if not isinstance(payload, Mapping):
        return {}
    info: dict[str, Any] = {}
    level = _count(payload.get("auth_level"))
    if level is not None:
        info["auth_level"] = level
    name = _text(payload.get("auth_level_name"), 64)
    if name is not None:
        info["auth_level_name"] = name
    return info

"""A deterministic human view of the analyst report (Task 20).

Fixed templates over structured values. No LLM, no generated prose, no phrasing
that depends on anything but the report: the same report renders to the same
characters, and every line is traceable to a field a named engine produced.

Presentation only
-----------------

Nothing here decides anything. It does not rank, weigh, summarise a verdict into
advice, or turn a relationship into an accusation — and it never recommends an
action. A MALICIOUS assessment is a statement about an observable, not an
instruction: blocking shared or compromised infrastructure hurts bystanders, and
that decision needs organisational context this engine does not have.

Untrusted text reaches the terminal here
----------------------------------------

Provider labels, tags, error details and the observable itself are all
attacker-influenceable. Written straight to a terminal, a value containing
``\\r`` can overwrite the line above it and an ANSI sequence can recolour or
clear the screen — so a crafted domain could forge a whole report section that
an analyst would read as the engine's own words. :func:`safe_text` neutralises
that at the boundary, for display only: the canonical data is never modified,
and the JSON renderer keeps the original values because JSON has its own
escaping and no cursor to move.
"""

from __future__ import annotations

import unicodedata

from ti_recon.reporting.models import (
    AnalystInvestigationReport,
    ReportSection,
)

__all__ = [
    "COVERAGE_MEANING",
    "MAX_TEXT_FIELD",
    "STATUS_MEANING",
    "VERDICT_MEANING",
    "render_text",
    "safe_text",
]

#: How much of any single untrusted value reaches the terminal.
#:
#: A bounded field cannot push the rest of the report off the screen, which is
#: the cheap version of the same attack the control characters attempt.
MAX_TEXT_FIELD: int = 200

#: What a line may not contain.
#:
#: Everything in the Unicode C0/C1 control ranges plus the standalone line and
#: paragraph separators. That covers ESC (which starts every ANSI sequence), CR
#: (which returns the cursor to the start of the line), LF, NUL and the
#: bidirectional and formatting controls that reorder rendered text.
_REPLACEMENT = "�"


def safe_text(value: str, *, limit: int = MAX_TEXT_FIELD) -> str:
    """Make one untrusted value safe to print, without editing the data.

    Control characters become a replacement character rather than disappearing,
    so an analyst can see that something was there — silently deleting them
    would hide the attempt as well as defeat it. Ordinary Unicode is preserved:
    a legitimate internationalised domain must still be readable.
    """
    cleaned = "".join(_REPLACEMENT if _is_unsafe(char) else char for char in value[: limit + 1])
    if len(cleaned) > limit:
        return f"{cleaned[:limit]}…"
    return cleaned


def _is_unsafe(char: str) -> bool:
    """Control and separator characters, by Unicode category rather than by list.

    ``Cc`` is C0/C1 controls, ``Cf`` is formatting controls including the
    bidirectional overrides, ``Zl``/``Zp`` are the line and paragraph
    separators. Keying on the category means a character nobody thought of is
    handled the same way as the ones that are already known to be dangerous.
    """
    return unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"}


#: One plain sentence per verdict, printed under the verdict itself.
#:
#: The machine spelling is not self-explanatory to somebody triaging at speed,
#: and the two readings that cost the most are both silent: ``inconclusive``
#: taken for clean, and ``likely_benign`` taken for cleared. A reader should not
#: have to already know the policy to avoid either.
#:
#: Presentation, and a restatement rather than an addition — every sentence here
#: is Task 17's own rule in words. Nothing is derived, ranked or weighed, and the
#: keys are the enum values so a verdict without a sentence is impossible.
VERDICT_MEANING: dict[str, str] = {
    "malicious": ("The collected intelligence supports a malicious assessment of this observable."),
    "suspicious": (
        "There is meaningful adverse evidence, short of what this engine "
        "requires for a malicious verdict."
    ),
    "likely_benign": (
        "The evidence supports a likely-benign assessment. Not a guarantee of "
        "safety and not an allowlisting decision."
    ),
    "inconclusive": (
        "The available intelligence does not justify either direction. This is "
        "not a finding of clean, safe or not malicious."
    ),
}

#: One plain sentence per coverage status, printed under it.
#:
#: All four say the same thing in different amounts: this is about the *search*,
#: never about permission to act on what it found.
COVERAGE_MEANING: dict[str, str] = {
    "ready": "No material intelligence gap remains for triage.",
    "ready_with_limitations": (
        "Adequate for triage; the limitations below remain and are not material to the assessment."
    ),
    "needs_more_data": (
        "A material intelligence gap remains, and further permitted collection "
        "could still address it."
    ),
    "unresolved": (
        "A material intelligence gap remains that external intelligence cannot resolve from here."
    ),
}


def render_text(report: AnalystInvestigationReport) -> str:
    """The whole report, as fixed-template lines.

    Ordered so the answer an analyst came for is at the top: what it is, how
    confident the engine is that it is right, and whether the search behind that
    was adequate. Everything else explains those three.
    """
    lines: list[str] = []
    lines += _target(report)
    lines += _assessment(report)
    lines += _basis(report)
    lines += _opposition(report)
    lines += _explanations(report)
    lines += _conflicts(report)
    lines += _coverage(report)
    lines += _related(report)
    lines += _sources(report)
    lines += _workflow(report)
    return "\n".join(lines) + "\n"


def _heading(title: str) -> list[str]:
    return ["", title]


def _label(value: str) -> str:
    """An enum value as a word rather than a shout.

    ``ready_with_limitations`` becomes ``Ready with limitations``. The value
    itself is unchanged in JSON; this is only how it reads in a sentence.
    """
    return value.replace("_", " ").capitalize()


def _omitted[Item](section: ReportSection[Item]) -> list[str]:
    """Always say when a list was cut.

    An analyst who cannot see that something was left out has been told
    something false about the investigation.
    """
    if not section.omitted:
        return []
    return [f"  ... {section.omitted} more of {section.total} not shown"]


def _empty(message: str) -> list[str]:
    return [f"  {message}"]


def _target(report: AnalystInvestigationReport) -> list[str]:
    return [
        "Target",
        f"  {report.target.object_type.value}: {safe_text(report.target.canonical_value)}",
    ]


def _assessment(report: AnalystInvestigationReport) -> list[str]:
    assessment, readiness = report.assessment, report.readiness
    lines = _heading("Assessment")
    lines.append(f"  Verdict: {assessment.verdict.value.upper()}")
    # Every machine value gets a sentence, because reading the spelling is not
    # the same as knowing what it claims. `.get` rather than `[]`: a verdict
    # added later must degrade to no sentence, never to a traceback in a
    # renderer.
    meaning = VERDICT_MEANING.get(assessment.verdict.value)
    if meaning is not None:
        lines.append(f"    {meaning}")
    # The band alone. The canonical STIX integer stays in the JSON contract,
    # where a consumer that wants it knows what it means — printed here beside
    # a verdict it reads as "50% likely malicious", which is a different claim
    # from the one Task 17 makes. Confidence is about whether the *assessment*
    # is correct, and there is no calibration behind any probability.
    lines.append(f"  Confidence: {_label(assessment.confidence)}")
    # "TI coverage" rather than "Readiness": READY means the external-intelligence
    # collection was adequate for triage, and a reader glancing at "Readiness:
    # READY" can take it for ready to close, ready to block, or incident-ready —
    # none of which this engine says or could say.
    lines.append(f"  TI coverage: {_label(readiness.status)}")
    coverage_meaning = COVERAGE_MEANING.get(readiness.status)
    if coverage_meaning is not None:
        lines.append(f"    {coverage_meaning}")
    lines.append(f"  Verdict rule: {safe_text(assessment.verdict_rule_id)}")
    if assessment.confidence_caps:
        capped = ", ".join(safe_text(item, limit=60) for item in assessment.confidence_caps)
        lines.append(f"  Confidence limited by: {capped}")
    return lines


def _basis(report: AnalystInvestigationReport) -> list[str]:
    """What the verdict rested on, in Task 17's own terms."""
    section = report.assessment_basis
    lines = _heading("Basis")
    if not section.items:
        lines += _empty("No claim supported the assessment.")
        return lines
    for item in section.items:
        lines.append(f"  - {safe_text(item.semantic, limit=64)} ({item.effect})")
        lines.append(f"      role: {item.role} / {item.decision_role}")
        lines.append(f"      scope: {item.scope}")
        lines.append(f"      source: {safe_text(item.source_family, limit=64)}")
    return lines + _omitted(section)


def _opposition(report: AnalystInvestigationReport) -> list[str]:
    """What pushed the other way, under a heading that says so.

    Task 17 reached its verdict *despite* these, and an analyst needs to see
    them — but listing them under "Basis" would put a benign assertion among
    the reasons an object was called malicious. Same records, same roles,
    different heading.
    """
    section = report.opposing_evidence
    if not section.items:
        return []
    lines = _heading("Evidence against this assessment")
    for item in section.items:
        lines.append(f"  - {safe_text(item.semantic, limit=64)} ({item.effect})")
        lines.append(f"      role: {item.role} / {item.decision_role}")
        lines.append(f"      scope: {item.scope}")
        lines.append(f"      source: {safe_text(item.source_family, limit=64)}")
    return lines + _omitted(section)


def _explanations(report: AnalystInvestigationReport) -> list[str]:
    """Only what Task 16 linked to specific evidence.

    The count of linked evidence is shown so an explanation reads as covering
    those items and not the investigation.
    """
    section = report.alternative_explanations
    lines = _heading("Alternative explanations")
    if not section.items:
        lines += _empty("None linked to the evidence behind this assessment.")
    else:
        for item in section.items:
            covered = len(item.explains_evidence_ids)
            lines.append(
                f"  - {safe_text(item.reason_code, limit=64)}"
                f" (applies to {covered} evidence item{'' if covered == 1 else 's'})"
            )
            lines.append(f"      scope: {item.scope}")
        lines += _omitted(section)

    unexplained = report.unexplained_evidence
    if unexplained.items:
        lines.append(
            f"  {unexplained.total} directional finding"
            f"{'' if unexplained.total == 1 else 's'} not accounted for by any explanation."
        )
    return lines


def _conflicts(report: AnalystInvestigationReport) -> list[str]:
    """Disagreements, shown as disagreements."""
    section = report.conflicts
    if not section.items:
        return []
    lines = _heading("Unresolved disagreement")
    for item in section.items:
        lines.append(f"  - {safe_text(item.proposition_ref, limit=120)}")
        lines.append(
            f"      malicious: {len(item.malicious_claim_ids)}"
            f" / benign: {len(item.benign_claim_ids)}"
        )
    return lines + _omitted(section)


def _coverage(report: AnalystInvestigationReport) -> list[str]:
    """Gaps and limitations, with the distinctions Task 18 drew.

    A completed check that held nothing is not reassurance, and a check nobody
    ran is not the same as one that came back empty — so the yield is printed
    beside the completion rather than instead of it.
    """
    lines = _heading("Coverage")
    lines.append("  (how adequate the intelligence was — not a decision about what to do)")
    lines.append(
        f"  Adequacy: {report.readiness.coverage_adequacy}"
        f" | continuation: {report.readiness.continuation_state}"
    )
    gaps = report.gaps
    if gaps.items:
        lines.append("  Material gaps:")
        for item in gaps.items:
            lines.append(
                f"    - {safe_text(item.capability or item.requirement_id, limit=64)}"
                f": {item.gap_type} ({item.criticality})"
            )
        lines += [f"  {line.strip()}" for line in _omitted(gaps)]
    else:
        lines.append("  No material gaps.")

    limitations = report.limitations
    if limitations.items:
        lines.append("  Limitations:")
        for limitation in limitations.items:
            lines.append(f"    - {safe_text(limitation.detail, limit=160)}")
        lines += [f"  {line.strip()}" for line in _omitted(limitations)]
    return lines


def _related(report: AnalystInvestigationReport) -> list[str]:
    """Related observables, described as relationships and nothing more.

    No item here is called an indicator. Where this run separately assessed an
    object, that is stated explicitly; where it did not, the absence of a
    verdict is the honest answer rather than an implied one.
    """
    section = report.related_observables
    if not section.items:
        return []
    lines = _heading("Related observables")
    lines.append(
        "  (relationships observed or reported; not indicators, and not "
        "assessments of these objects)"
    )
    for item in section.items:
        lines.append(f"  - {item.object_type.value}: {safe_text(item.canonical_value)}")
        lines.append(
            f"      relationship: {safe_text(item.relationship_type, limit=64)} ({item.direction})"
        )
        lines.append(f"      basis: {item.observation_basis or 'unstated'}")
        if item.assessed:
            lines.append("      separately assessed in this investigation")
    return lines + _omitted(section)


#: What a run status means, for the three that are read wrongly by default.
#:
#: ``not_configured`` is the one this exists for: printed bare beside a provider
#: name it reads as an outage or a rejected key, when the source was never
#: contacted at all. ``no_data`` and ``partial`` are the other two an analyst can
#: turn into reassurance without noticing.
#:
#: The rest are printed unannotated — ``success``, ``error``, ``quota_exceeded``
#: and the others say what they mean, and a gloss on every line would bury the
#: three that need one.
STATUS_MEANING: dict[str, str] = {
    "not_configured": "not checked; no credential is available for this account",
    "no_data": "checked; held nothing applicable (not evidence of safety)",
    "not_supported": "does not answer this kind of observable",
    "partial": "answered in part",
}


def _sources(report: AnalystInvestigationReport) -> list[str]:
    """Who was asked, as provenance. Never a count of who agreed.

    The authoritative answer to "which sources did you use?". A source absent
    from this section was not consulted, whatever the installation ships and
    whatever the caller has configured — so the heading says so rather than
    leaving a reader to infer it from a list they cannot tell is exhaustive.
    """
    section = report.source_checks
    lines = _heading("Source checks")
    lines.append("  (the sources actually consulted; anything not listed was not asked)")
    if not section.items:
        lines += _empty("No source was consulted.")
        return lines
    for item in section.items:
        detail = f"  - {safe_text(item.provider_id, limit=64)} / {item.capability}: {item.status}"
        if item.error_category:
            detail = f"{detail} ({item.error_category})"
        meaning = STATUS_MEANING.get(item.status)
        if meaning is not None:
            detail = f"{detail} — {meaning}"
        if item.cache_hit:
            # A cached answer is a real check and not a fresh disclosure. Both
            # halves matter: the result stands, and the source was not contacted
            # again for it.
            detail = f"{detail} [cached; source not contacted again]"
        lines.append(detail)
    return lines + _omitted(section)


def _workflow(report: AnalystInvestigationReport) -> list[str]:
    investigation = report.investigation
    rounds = investigation.rounds
    return [
        *_heading("Workflow"),
        f"  {rounds} round{'' if rounds == 1 else 's'}, stopped: {investigation.stop_reason}",
        f"  Evaluated at: {investigation.evaluated_at.isoformat()}",
        f"  Report schema: {report.schema_version}",
    ]

"""The report is the external boundary, so it is where leaks land (Task 20).

Everything the engine holds passes through this layer on its way to a terminal,
a file or another process. Three things must never make it out: a credential, a
raw provider payload, and a control sequence that lets provider-influenced text
forge the engine's own words.
"""

from __future__ import annotations

import json

import pytest

from fixtures.investigation import claim_evidence, file_root, spec
from fixtures.investigation.stack import FAKE_SECRET_MARKER, InvestigationStack, ScriptedProvider
from fixtures.reporting import malicious_report
from ti_recon.enums import ProviderCapability
from ti_recon.investigation import InvestigationRequest
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reporting import build_analyst_report, render_text
from ti_recon.reporting.text import MAX_TEXT_FIELD, safe_text

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
DIGEST = "a" * 64

#: Unmistakable, so a match cannot be a coincidence.
SECRETS = (FAKE_SECRET_MARKER, "SUPER_SECRET_VT_KEY_123", "SUPER_SECRET_ABUSE_KEY_456")


@pytest.mark.asyncio
async def test_no_credential_reaches_either_rendering() -> None:
    """The fixture gives every provider a key; none of them appears anywhere.

    Both formats are searched, because they are built by different code: JSON
    comes from the model and text from the renderer, and a leak in one would not
    show up in the other.
    """
    _, report = await malicious_report()
    document = report.model_dump_json()
    rendered = render_text(report)

    for secret in SECRETS:
        assert secret not in document, secret
        assert secret not in rendered, secret


@pytest.mark.asyncio
async def test_no_credential_bearing_field_name_appears() -> None:
    """Not just the values: the shapes that would carry them.

    A field called ``authorization`` in a public contract is a leak waiting for
    somebody to populate it.
    """
    _, report = await malicious_report()
    keys = _all_keys(json.loads(report.model_dump_json()))

    for forbidden in ("api_key", "apikey", "auth_key", "authorization", "password", "secret"):
        assert not any(forbidden in key for key in keys), forbidden


def _all_keys(document: object) -> set[str]:
    """Every key at every depth, so a nested leak cannot hide."""
    match document:
        case dict():
            found = set(document.keys())
            for value in document.values():
                found |= _all_keys(value)
            return found
        case list() | tuple():
            found: set[str] = set()
            for value in document:
                found |= _all_keys(value)
            return found
        case _:
            return set()


# --------------------------------------------------------------------------- #
# Terminal injection
# --------------------------------------------------------------------------- #

_ESCAPE = "\x1b[31m"
_HOSTILE = f"evil\r\nAssessment\n  Verdict: LIKELY_BENIGN{_ESCAPE}\x07"


def test_control_characters_cannot_forge_a_report_section() -> None:
    """The attack this function exists to stop.

    A value carrying CR and LF can start what looks like a new section, and an
    analyst reading the terminal has no way to tell the forged lines from the
    engine's. Neutralised at the boundary, and visibly: the replacement
    character shows something was removed rather than hiding the attempt.
    """
    rendered = safe_text(_HOSTILE)

    assert "\r" not in rendered
    assert "\n" not in rendered
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "�" in rendered


def test_ordinary_unicode_survives() -> None:
    """A legitimate internationalised value must still be readable.

    Stripping everything non-ASCII would be a different bug: an analyst
    investigating a Cyrillic or CJK domain needs to see it.
    """
    assert safe_text("münchen-bücher.example") == "münchen-bücher.example"
    assert safe_text("日本語.example") == "日本語.example"


def test_a_long_value_is_bounded_and_says_so() -> None:
    """A field cannot push the report off the screen."""
    rendered = safe_text("A" * 5000)

    assert len(rendered) <= MAX_TEXT_FIELD + 1
    assert rendered.endswith("…")


@pytest.mark.asyncio
async def test_hostile_provider_text_cannot_forge_lines_in_a_real_report() -> None:
    """End to end, with the hostile value where a provider would put it."""
    hostile = ScriptedProvider(
        spec(
            f"repo{_HOSTILE[:0]}",
            family="fam\r\nforged",
            capabilities=frozenset({INTELLIGENCE, REPUTATION}),
        ),
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
    )
    stack = InvestigationStack(providers=[hostile])
    await stack.add_credentials()
    result = await stack.orchestrator.investigate(
        InvestigationRequest(root=file_root(DIGEST)), stack.context()
    )
    rendered = render_text(build_analyst_report(result))

    # The forged family name cannot start a line of its own.
    assert not any(line.strip().startswith("forged") for line in rendered.splitlines())
    assert "\r" not in rendered
    assert "\x1b" not in rendered


@pytest.mark.asyncio
async def test_json_keeps_the_canonical_value_and_escapes_it() -> None:
    """JSON has structural escaping and no cursor to move.

    Mutating canonical values to make a *terminal* safe would corrupt the
    machine contract for a problem the machine contract does not have.
    """
    _, report = await malicious_report()
    document = report.model_dump_json()

    parsed = json.loads(document)
    assert parsed["target"]["canonical_value"] == report.target.canonical_value

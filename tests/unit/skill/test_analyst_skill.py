"""The analyst Skill as an artifact (Task 21).

A Skill is instructions, so most of its quality is a matter of judgement no test
can settle. What a test *can* hold is the structure a host depends on, and the
handful of semantic rules whose loss would be silent and damaging — a related
observable becoming an indicator, ``NO_DATA`` becoming reassurance, provider
counts becoming a verdict.

Deliberately not asserted: exact prose. Wording will change and should; the
distinctions must not.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SKILL_DIR = Path(".claude/skills/ti-recon-analyst")
SKILL_FILE = SKILL_DIR / "SKILL.md"
REFERENCES = SKILL_DIR / "references"

#: The three tools the Skill may drive.
TOOLS = ("investigate_observable", "investigate_file", "provider_status")


@pytest.fixture(scope="module")
def skill() -> str:
    return SKILL_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def frontmatter(skill: str) -> dict[str, str]:
    """The YAML header, parsed without adding a YAML dependency.

    The header is flat ``key: value`` by design, so a two-line parser is enough
    and the repository gains no dependency for a test.
    """
    match = re.match(r"^---\n(.*?)\n---\n", skill, re.DOTALL)
    assert match, "SKILL.md must open with YAML frontmatter"
    fields: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" in line and not line.startswith(" "):
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    return fields


@pytest.fixture(scope="module")
def corpus(skill: str) -> str:
    """Every word of the Skill, for rules that may live in any file."""
    return "\n".join([skill, *(path.read_text(encoding="utf-8") for path in _references())])


def _references() -> list[Path]:
    return sorted(REFERENCES.glob("*.md"))


# --------------------------------------------------------------------------- #
# Structure the host depends on
# --------------------------------------------------------------------------- #


def test_the_skill_exists_where_claude_code_looks_for_it() -> None:
    """Project skills load from `.claude/skills/<name>/SKILL.md`."""
    assert SKILL_FILE.is_file()
    assert SKILL_DIR.name == "ti-recon-analyst"


def test_the_frontmatter_names_the_skill_and_says_when_to_use_it(frontmatter) -> None:
    """``description`` is the automatic trigger, so it has to be substantial."""
    assert frontmatter["name"] == "ti-recon-analyst"
    description = frontmatter["description"]
    assert len(description) > 120, "a one-line description will not discriminate"
    assert "argument-hint" in frontmatter


def test_the_description_names_the_inputs_that_should_trigger_it(frontmatter) -> None:
    """Concrete indicator types, so a real investigation request matches."""
    description = frontmatter["description"].lower()
    for term in ("url", "domain", "hash", "file", "investigate", "false positive"):
        assert term in description, term


def test_the_description_excludes_generic_security_education(frontmatter) -> None:
    """It must not hijack "what is a hash" or "write a URL parser".

    A trigger that fires on every security question is worse than no trigger:
    it spends a tool budget and buries the cases that needed it.
    """
    description = frontmatter["description"].lower()
    assert "not for" in description or "rather than" in description


def test_the_skill_grants_itself_no_tool_permissions(frontmatter) -> None:
    """Permission belongs to the user's configuration.

    An ``allowed-tools`` grant here would pre-authorise investigation tools the
    user never approved — and would undercut the explicit approval Claude Code
    requires for local file access.
    """
    assert "allowed-tools" not in frontmatter


def test_the_skill_stays_automatically_invocable(frontmatter) -> None:
    """It should activate on a real investigation request without being named."""
    assert frontmatter.get("disable-model-invocation", "false").lower() != "true"


def test_the_control_plane_stays_short(skill: str) -> None:
    """Detail belongs in references, which load only when needed."""
    assert len(skill.splitlines()) < 500


def test_every_referenced_file_exists(skill: str) -> None:
    """A pointer to a missing file is an instruction that silently does nothing."""
    named = set(re.findall(r"references/([a-z-]+\.md)", skill))
    assert named, "SKILL.md should route to its references"
    for name in named:
        assert (REFERENCES / name).is_file(), name


def test_the_skill_says_when_to_read_each_reference(skill: str) -> None:
    """Loaded on demand, not all three every time."""
    for name in ("interpretation.md", "response-style.md", "examples.md"):
        assert name in skill, name


# --------------------------------------------------------------------------- #
# Semantic guardrails
# --------------------------------------------------------------------------- #


def test_the_skill_drives_the_mcp_tools_and_not_the_cli(corpus: str) -> None:
    """MCP and the CLI are peers over the same application.

    Shelling out would bypass the tool boundary the host mediates — including
    the human approval required for local files.
    """
    for tool in TOOLS:
        assert tool in corpus, tool
    assert "ti-recon investigate" not in corpus
    assert "curl " not in corpus


def test_the_skill_refuses_to_pick_providers(corpus: str) -> None:
    """Task 13 ranks sources; a Skill choosing one makes results depend on it."""
    lowered = corpus.lower()
    assert "task 13" in lowered or "picks the applicable sources" in lowered
    assert "never" in lowered


def test_sources_are_never_counted(corpus: str) -> None:
    """No tally, anywhere. Provider majority is not how this engine decides."""
    lowered = corpus.lower()
    assert "votes" in lowered or "counting" in lowered
    assert "majority" in lowered


@pytest.mark.parametrize(
    ("subject", "must_mention"),
    [
        ("no_data", ("clean", "benign")),
        ("unattributed", ("bundled",)),
        ("not_configured", ("credential",)),
    ],
)
def test_the_coverage_vocabulary_is_explained_and_not_flattened(
    corpus: str, subject: str, must_mention
) -> None:
    """Each state means something different, and the differences are load-bearing."""
    lowered = corpus.lower()
    assert subject in lowered, subject
    for term in must_mention:
        assert term in lowered, f"{subject}: {term}"


def test_a_related_observable_is_not_an_indicator(corpus: str) -> None:
    """The rule that keeps a public resolver off a blocklist."""
    lowered = corpus.lower()
    assert "relationship is not an accusation" in lowered or "not indicators" in lowered
    assert "assessed" in lowered


def test_confidence_is_not_a_probability(corpus: str) -> None:
    """A number beside a verdict reads as "likely malicious", which it is not."""
    lowered = corpus.lower()
    assert "probability" in lowered
    assert "assessment is correct" in lowered


def test_coverage_is_not_permission_to_act(corpus: str) -> None:
    """READY is about the search, never about the response."""
    lowered = corpus.lower()
    assert "ti coverage" in lowered
    assert "ready to block" in lowered or "ready to close" in lowered


def test_the_local_file_rule_requires_an_explicit_user_selection(corpus: str) -> None:
    """No browsing, no enumerating, no picking a file on the model's initiative."""
    lowered = corpus.lower()
    assert "explicitly identified" in lowered or "explicitly" in lowered
    assert "browse" in lowered
    assert ".env" in lowered
    # And the privacy fact a user needs to hear.
    assert "never uploaded" in lowered or "not uploaded" in lowered
    assert "detonation" in lowered


def test_external_pivot_disclosure_requires_explicit_intent(corpus: str) -> None:
    """Two switches, because two different disclosures."""
    lowered = corpus.lower()
    assert "external pivot" in lowered
    assert "silently" in lowered


def test_more_detail_never_costs_a_new_lookup(corpus: str) -> None:
    """The distinction with the largest cost difference in the whole Skill."""
    lowered = corpus.lower()
    assert "no new lookups" in lowered or "new tool call" in lowered
    assert "broader collection" in lowered


def test_depth_is_never_escalated_on_the_models_initiative(corpus: str) -> None:
    """A suspicious result is not consent to spend more quota."""
    lowered = corpus.lower()
    assert "escalate" in lowered
    assert "quota" in lowered


def test_the_skill_makes_no_remediation_decision(corpus: str) -> None:
    """It may state the assessment; the response is the organisation's call."""
    lowered = corpus.lower()
    assert "quarantine" in lowered
    assert "response decision" in lowered or "organisation" in lowered


def test_no_credential_is_ever_requested_in_chat(corpus: str) -> None:
    """A key pasted into a conversation is a key in a transcript."""
    lowered = corpus.lower()
    assert "paste" in lowered
    assert "reconnect" in lowered


def test_the_skill_contains_no_secret_shaped_value(corpus: str) -> None:
    """Instructions are committed; a placeholder key would be committed too."""
    for pattern in (
        r"api[_-]?key\s*[=:]\s*\S{8,}",
        r"token\s*[=:]\s*\S{8,}",
        r"Bearer\s+[A-Za-z0-9._-]{8,}",
    ):
        assert not re.search(pattern, corpus, re.IGNORECASE), pattern


# --------------------------------------------------------------------------- #
# The examples teach the hard cases
# --------------------------------------------------------------------------- #


def test_the_examples_cover_the_cases_most_easily_mis_summarised() -> None:
    """Each of these has a specific way of going wrong in a summary."""
    examples = (REFERENCES / "examples.md").read_text(encoding="utf-8").lower()
    for case in (
        "likely benign",
        "inconclusive",
        "unresolved",
        "no_data",
        "unattributed",
        "offline",
        "should i block it",
    ):
        assert case in examples, case


def test_the_likely_benign_example_refuses_the_word_safe() -> None:
    """The single most dangerous summary this Skill could produce."""
    examples = (REFERENCES / "examples.md").read_text(encoding="utf-8")
    section = examples.split("## D.")[1].split("## E.")[0].lower()
    assert "incomplete" in section
    assert "clean" in section or "safe" in section  # named as words to avoid

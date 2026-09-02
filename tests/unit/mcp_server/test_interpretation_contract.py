"""The semantics an MCP client gets without a Skill (Task 22 correction).

A project Skill lives in ``.claude/skills/`` of *this repository*. A client that
merely connects the server — Claude Web through the hosted connector, most
obviously — never receives it. So every rule an analyst must not get wrong has
to be reachable from the three things the protocol itself carries:

* the server ``instructions``,
* each tool's ``description``,
* the structured ``outputSchema`` derived from the Task 20 report model.

These tests read exactly those three. **No test in this module opens a Skill
file**, and one of them asserts the Skill directory is untouched by everything
asserted here — because "the contract is correct" and "the contract plus a Skill
is correct" are different claims, and only the first one holds for most clients.

Structural, never stochastic
----------------------------

Nothing here asks a model what it would say. Each test names a distinction that
was got wrong against the live deployment, then asserts the exposed surface
states it in the direction that matters — so a text merely *mentioning* the word
would not pass.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

import pytest
from mcp import Client
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl

from fixtures.investigation import claim_evidence, spec
from fixtures.investigation.stack import ScriptedProvider
from fixtures.mcp_server import scripted_runtime
from ti_recon.enums import ProviderCapability
from ti_recon.mcp_server.server import (
    REMOTE_INSTRUCTIONS,
    SERVER_INSTRUCTIONS,
    STDIO_INSTRUCTIONS,
    build_remote_server,
    build_stdio_server,
)
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reporting.schema import report_json_schema

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
DIGEST = "a" * 64


class _NeverCalled(TokenVerifier):
    """A verifier the profile builder must not need.

    Listing tools is a protocol operation, not an authenticated one in these
    tests: the remote *profile* is what is under test, not its bearer check,
    which has its own suite. Raising rather than returning ``None`` means a test
    that accidentally depended on authentication fails loudly.
    """

    async def verify_token(self, token: str) -> AccessToken | None:  # pragma: no cover
        raise AssertionError("the interpretation contract must not verify a token")


def _auth_settings() -> AuthSettings:
    return AuthSettings(
        issuer_url=AnyHttpUrl("https://idp.example.invalid/oauth2"),
        resource_server_url=AnyHttpUrl("https://ti-recon.example.invalid/mcp"),
        required_scopes=["ti-recon:investigate"],
    )


async def _runtime():
    provider = ScriptedProvider(
        spec("repo", family="fam_repo", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
    )
    runtime, _ = await scripted_runtime([provider])
    return runtime


async def _surface(*, hosted: bool) -> dict[str, Any]:
    """Everything one deployment profile puts on the wire, and nothing else.

    Assembled from a live ``Client`` session rather than from the Python
    constants, because what a client can act on is what survives serialization —
    a description held only on a function object is guidance to nobody.
    """
    runtime = await _runtime()
    server = (
        build_remote_server(runtime, auth=_auth_settings(), token_verifier=_NeverCalled())
        if hosted
        else build_stdio_server(runtime)
    )
    async with Client(server) as client:
        instructions = client.instructions or ""
        tools = {item.name: item for item in (await client.list_tools()).tools}
    return {
        "instructions": instructions,
        "tools": tools,
        "text": _flatten(instructions, tools),
        # The same surface with the optional discovery document removed.
        "without_instructions": _without_instructions(tools),
    }


def _prose(value: str | None) -> str:
    """One description as a client reads it: lowered, whitespace collapsed.

    A docstring wraps at the source's margin, so a sentence a test looks for is
    routinely split by a newline and an indent that no reader sees. Matching on
    the collapsed form asserts what was said rather than where it happened to
    break.
    """
    return " ".join((value or "").split()).lower()


def _flatten(instructions: str, tools: dict[str, Any]) -> str:
    """Every word a client receives about how to read a result, lowered.

    Instructions, tool descriptions and the output schemas together — the whole
    interpretive surface, so a test asserts "the client was told this" rather
    than "this particular field says it". Where a specific *location* matters,
    the test looks there instead.
    """
    return "\n".join([" ".join(instructions.split()), _without_instructions(tools)]).lower()


def _without_instructions(tools: dict[str, Any]) -> str:
    """What a client gets having ignored the optional discovery path.

    Server ``instructions`` arrive with ``initialize``, and a 2026-07-28 client
    may send a self-contained ``tools/call`` without ever asking for them. So
    they are reinforcement, never the sole carrier: whatever a reader must not
    get wrong has to survive here, in the tool descriptions and the schemas a
    client receives with the tools themselves.
    """
    parts: list[str] = []
    for tool in tools.values():
        parts.append(_prose(tool.description))
        parts.append(json.dumps(tool.input_schema, sort_keys=True))
        if tool.output_schema is not None:
            parts.append(json.dumps(tool.output_schema, sort_keys=True))
    return "\n".join(parts).lower()


def report_schema() -> dict[str, Any]:
    """The published report schema, generated from the Task 20 model.

    Called rather than fixtured so each test reads as a statement about the
    contract a client fetches, not about a cached object a fixture handed over.
    """
    return report_json_schema()


def _field(schema: dict[str, Any], model: str, field: str) -> dict[str, Any]:
    """One field's schema entry, by model name.

    Addressed through ``$defs`` so a test names the model and the field rather
    than a path that changes whenever the report is restructured.
    """
    return dict(schema["$defs"][model]["properties"][field])


def _description(schema: dict[str, Any], model: str, field: str) -> str:
    entry = _field(schema, model, field)
    description = entry.get("description")
    assert description, f"{model}.{field} carries no description"
    return _prose(str(description))


# --------------------------------------------------------------------------- #
# The contract stands alone
# --------------------------------------------------------------------------- #


def test_no_expectation_in_this_module_comes_from_the_skill() -> None:
    """The acceptance rule, asserted rather than intended.

    Every other test here builds its expectation from ``src`` and from the live
    protocol surface. Nothing in this module opens a file under ``.claude``, so
    deleting the project Skill could not change one of their outcomes — which is
    exactly the claim being made about a client that never had it.

    Checked over the AST rather than the raw text, because the prose explaining
    a rule necessarily names the thing the code may not touch: docstrings and
    comments are exempt, and every *executed* string literal is not. This
    function is exempt from its own rule, being the only code here that has to
    spell out what it forbids.
    """
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    checker = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == test_no_expectation_in_this_module_comes_from_the_skill.__name__
    )
    exempt = {id(node) for node in ast.walk(checker)}
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }

    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in exempt
        and id(node) not in docstrings
    ]
    for value in literals:
        assert "claude" not in value.lower(), value

    # And nothing is imported from a Skill package either — there is none, and
    # an import is the other way a filesystem artifact becomes a dependency.
    modules = {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module
    }
    allowed = ("ti_recon", "fixtures", "mcp", "pydantic", "pathlib", "typing", "__future__")
    unexpected = sorted(module for module in modules if not module.startswith(allowed))
    assert unexpected == []


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_both_profiles_publish_the_shared_semantic_core(hosted: bool) -> None:
    """Neither deployment may be the one that omits a rule.

    A hosted client and a local one read the same report and can misread it the
    same way. Only the credential paragraph differs between the profiles;
    everything about *meaning* is shared.
    """
    surface = await _surface(hosted=hosted)
    assert SERVER_INSTRUCTIONS in surface["instructions"]
    expected = REMOTE_INSTRUCTIONS if hosted else STDIO_INSTRUCTIONS
    assert surface["instructions"] == expected


# --------------------------------------------------------------------------- #
# E — INCONCLUSIVE is not clean
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_the_client_is_told_inconclusive_is_not_clean(hosted: bool) -> None:
    """The verdict most often read as reassurance.

    "Nothing conclusive" and "nothing wrong" are a step apart in English and a
    world apart in triage, so the contract denies the reading explicitly rather
    than leaving the machine spelling to speak for itself.
    """
    surface = await _surface(hosted=hosted)
    text = surface["text"]
    assert "inconclusive" in text
    assert "never means clean" in text or "does not mean clean" in text

    verdict = _description(report_schema(), "AssessmentSummary", "verdict")
    assert "cannot justify either direction" in verdict
    assert "not mean clean, safe" in verdict


# --------------------------------------------------------------------------- #
# A — NOT_CONFIGURED, and no credential onboarding claimed
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_not_configured_is_published_as_not_checked(hosted: bool) -> None:
    """The distinction that produced the wrong live answer.

    ``not_configured`` says nothing was contacted. Read as a provider failure it
    becomes "the source was down"; read as a completed check it becomes "nothing
    known about this". Both are claims the record cannot support.
    """
    surface = await _surface(hosted=hosted)
    assert "not_configured" in surface["text"]

    status = _description(report_schema(), "SourceCheckItem", "status")
    assert "not checked" in status
    for denied in ("offline", "unreachable", "found nothing"):
        assert denied in status, denied


@pytest.mark.asyncio
async def test_the_hosted_profile_claims_no_credential_onboarding() -> None:
    """The correction itself.

    A hosted caller has no server environment to edit and no process to restart.
    Left unsaid, a client supplies the local model it already knows — which is
    what happened — so the hosted profile states the absence rather than leaving
    a gap for a plausible guess to fill.
    """
    surface = await _surface(hosted=True)
    text = surface["text"]

    assert "not available in this version" in text
    for forbidden in (
        "configure it locally",
        "configured locally",
        "reconnect the server",
        "restart the server",
        "environment variable names",
        ".env",
    ):
        assert forbidden not in text, forbidden
    # And it says what a client must never do instead.
    assert "never ask" in text
    assert "paste a provider api key" in text or "provider api key in the conversation" in text


@pytest.mark.asyncio
async def test_the_local_profile_keeps_its_real_setup_step() -> None:
    """Accurate advice is not removed for being inapplicable elsewhere.

    Over stdio the analyst *does* own the process and the environment it reads,
    so describing that is correct. The fix was never "say less"; it was "stop
    saying the local thing to somebody remote".
    """
    surface = await _surface(hosted=False)
    text = surface["text"]

    assert "environment variables" in text
    assert "restarted or reconnected" in text or "restart or reconnect" in text
    # But a key still never travels through a conversation.
    assert "never ask" in text
    assert "not available in this version" not in text


# --------------------------------------------------------------------------- #
# B, C, D — checked-and-empty, cached, and configured
# --------------------------------------------------------------------------- #


def test_no_data_is_published_as_a_completed_check_and_never_as_safety() -> None:
    """A source that held nothing completed its check and proved nothing."""
    schema = report_schema()

    status = _description(schema, "SourceCheckItem", "status")
    assert "held nothing applicable" in status
    assert "never clean, safe" in status

    yield_ = _description(schema, "CoverageCheckItem", "information_yield")
    assert "not evidence of safety" in yield_
    assert "never means clean or benign" in yield_


def test_unattributed_keeps_its_own_meaning() -> None:
    """Neither ``no_data`` nor absence.

    One call answered several capabilities and the record cannot say which
    returned what. Rendering it as ``no_data`` asserts the source held nothing,
    which is a claim about content the record does not carry.
    """
    yield_ = _description(report_schema(), "CoverageCheckItem", "information_yield")
    assert "unattributed" in yield_
    assert "cannot say which" in yield_
    assert "neither" in yield_ and "absence" in yield_


def test_a_cache_hit_is_published_as_a_check_that_made_no_request() -> None:
    """Both halves, because either alone is wrong.

    The answer stands — it is a real check — and the source was not contacted
    again for it. A client that says "I queried it" is overstating the
    disclosure; one that says "it wasn't checked" is understating the evidence.
    """
    schema = report_schema()

    cache = _description(schema, "SourceCheckItem", "cache_hit")
    assert "reused" in cache
    assert "not contacted again" in cache
    assert "freshly queried" in cache

    called = _description(schema, "SourceCheckItem", "called_provider")
    assert "physically contacted" in called


@pytest.mark.asyncio
async def test_configured_is_published_as_stored_and_not_as_working() -> None:
    """Five things a stored credential does not establish, named individually.

    A single "not validated" would leave three of them to inference, and a
    client inferring "configured, therefore this source will answer" is how an
    expired key becomes a silent coverage gap.
    """
    surface = await _surface(hosted=True)
    description = _prose(surface["tools"]["provider_status"].description)

    assert "not that it is valid" in description
    for absent in ("authentication would succeed", "quota remains", "healthy", "entitlement"):
        assert absent in description, absent
    # And configuration is not consultation.
    assert "was not thereby queried" in description
    assert "source_checks" in description


# --------------------------------------------------------------------------- #
# F, H — what decided it, and what disagreed
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_the_client_is_told_not_to_count_sources(hosted: bool) -> None:
    """ "Five providers say malicious" is not this engine's reasoning.

    And the family rule is the half that is easy to lose: three product names
    from one organisation look like three confirmations and are one origin.
    """
    surface = await _surface(hosted=hosted)
    text = surface["text"]

    assert "never votes" in text
    assert "does not count who agreed" in text
    assert "source family" in text and "one origin" in text

    family = _description(report_schema(), "BasisItem", "source_family")
    assert "never a vote" in family
    assert "cannot corroborate each other" in family


def test_basis_and_opposition_are_published_as_separate_channels() -> None:
    """Under one heading meaning "why", a benign claim reads as a reason.

    The report keeps two sections and the schema says which is which, so a
    client has no reason to merge them and a documented reason not to.
    """
    schema = report_schema()
    report = schema["properties"]

    assert "assessment_basis" in report
    assert "opposing_evidence" in report
    assert "why the assessment was" in _prose(report["assessment_basis"].get("description"))
    opposing = _prose(report["opposing_evidence"].get("description"))
    assert "argued against the verdict" in opposing
    assert "kept apart from the basis" in opposing

    conflict = _prose(schema["$defs"]["ConflictItem"].get("description"))
    assert "preserved" in conflict
    for denied in ("averaged", "balanced", "overruled"):
        assert denied in conflict, denied


def test_an_explanation_is_published_as_covering_linked_evidence_only() -> None:
    """One explained detection is not a false-positive case."""
    explains = _description(report_schema(), "ExplanationItem", "explains_evidence_ids")
    assert "and nothing else" in explains
    assert "does not explain the investigation" in explains
    assert "unexplained_evidence" in explains


# --------------------------------------------------------------------------- #
# Confidence, coverage and the boundary of the answer
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_confidence_is_published_as_correctness_not_likelihood(hosted: bool) -> None:
    """MEDIUM is not "a 50% chance this is malware".

    There is no calibration behind any such number, so the contract denies the
    reading in the instructions *and* on both fields a client could take it
    from.
    """
    surface = await _surface(hosted=hosted)
    assert "not a probability that the observable is malicious" in surface["text"]

    schema = report_schema()
    band = _description(schema, "AssessmentSummary", "confidence")
    assert "assessment being correct" in band
    assert "not the probability" in band
    assert "severity" in band

    stix = _description(schema, "AssessmentSummary", "confidence_stix")
    assert "not a percentage likelihood" in stix


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_coverage_is_published_as_adequacy_not_authorization(hosted: bool) -> None:
    """READY is a statement about the search, not permission to act on it.

    Task 18 owns "ready" for coverage adequacy; a reader taking it for "ready to
    block" is acting on a decision this engine explicitly declines to make.
    """
    surface = await _surface(hosted=hosted)
    text = surface["text"]
    assert "never permission to block" in text or "is never permission" in text

    status = _description(report_schema(), "ReadinessSummary", "status")
    assert "adequate for analyst triage" in status
    assert "not permission to" in status
    assert "never means safe" in status


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_source_checks_is_published_as_the_authority_on_what_was_asked(
    hosted: bool,
) -> None:
    """Shipped, applicable and configured are three states, and none is asked."""
    surface = await _surface(hosted=hosted)
    text = surface["text"]
    assert "source_checks is the authority" in text
    assert "was not thereby asked" in text

    schema = report_schema()
    section = _prose(schema["$defs"]["SourceCheckItem"].get("description"))
    assert "authority for what was actually consulted" in section
    assert "was not queried" in section


# --------------------------------------------------------------------------- #
# I, L — relationships, and whose knowledge a sentence is
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_a_related_observable_is_published_as_a_relationship(hosted: bool) -> None:
    """``assessed=false`` means no verdict was reached about that object.

    Promoting one to an indicator is how a public resolver reaches a blocklist,
    so the schema states the negative rather than relying on the section name.
    """
    surface = await _surface(hosted=hosted)
    assert "assessed=false is a relationship" in surface["text"]

    assessed = _description(report_schema(), "RelatedObservableItem", "assessed")
    assert "no verdict about it is implied" in assessed
    assert "not an indicator" in assessed
    assert "must not be described as malicious" in assessed


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_the_client_is_told_to_label_its_own_knowledge(hosted: bool) -> None:
    """A host model knows things TI Recon never collected.

    That is useful and it is not evidence. Unlabelled, it enters the answer
    indistinguishable from a provider finding — and a reader cannot then tell
    which sentences the engine stands behind.
    """
    surface = await _surface(hosted=hosted)
    text = surface["text"]
    assert "from your own knowledge" in text
    assert "labelled as yours" in text
    assert "never be presented as ti recon evidence" in text


# --------------------------------------------------------------------------- #
# Disclosure, and the tool that is not there
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_hosted_investigation_tool_discloses_what_it_sends() -> None:
    """An analyst deciding whether to submit needs to know it leaves.

    Stated on the tool a caller reads before invoking it, not only in a
    document somewhere.
    """
    surface = await _surface(hosted=True)
    description = _prose(surface["tools"]["investigate_observable"].description)

    assert "may be sent to external" in description
    assert "provider selection is automatic" in description
    assert "no credential is ever an argument" in description


@pytest.mark.asyncio
async def test_the_hosted_surface_still_has_no_file_tool() -> None:
    """Unchanged by this correction, and asserted beside it.

    Wording work is exactly the kind of change that quietly alters a surface, so
    the profile difference that matters most is re-checked here rather than
    assumed from another module.
    """
    hosted = await _surface(hosted=True)
    local = await _surface(hosted=False)

    assert set(hosted["tools"]) == {"investigate_observable", "provider_status"}
    assert set(local["tools"]) == {
        "investigate_observable",
        "investigate_file",
        "provider_status",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_the_instructions_stay_within_a_practical_budget(hosted: bool) -> None:
    """Concise enough to be read, in a place a client actually reads.

    Instructions compete with everything else in a context window. The detailed
    per-value vocabulary lives in the output schema, which is consulted when a
    field is being interpreted rather than carried permanently.
    """
    surface = await _surface(hosted=hosted)
    assert len(surface["instructions"].encode()) < 4096


# --------------------------------------------------------------------------- #
# The contract survives a client that never reads the instructions
# --------------------------------------------------------------------------- #

#: Every reading that would be *confidently wrong*, and where it is denied.
#:
#: Each entry is a misinterpretation an analyst could act on, paired with
#: phrases that must appear somewhere a client receives *with the tools* — not
#: in the server instructions, which a 2026-07-28 client may never fetch.
MISREADINGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "INCONCLUSIVE means clean",
        ("cannot justify either direction", "not mean clean, safe"),
    ),
    (
        "NOT_CONFIGURED means checked and empty",
        ("not checked", "offline", "unreachable", "found nothing"),
    ),
    (
        "NO_DATA means benign",
        ("never clean, safe", "not evidence of safety"),
    ),
    (
        "confidence_stix is a probability of maliciousness",
        ("not a percentage likelihood", "not the probability"),
    ),
    (
        "a cache hit means the source was contacted again",
        ("not contacted again", "freshly queried"),
    ),
    (
        "configured means the credential works",
        ("not that it is valid", "authentication would succeed", "quota remains"),
    ),
    (
        "a related observable with assessed=false is a confirmed indicator",
        (
            "no verdict about it is implied",
            "not an indicator",
            "must not be described as malicious",
        ),
    ),
    (
        "counting providers is corroboration",
        ("never a vote", "cannot corroborate each other"),
    ),
    (
        "coverage readiness authorises an action",
        ("not permission to", "never means safe"),
    ),
    (
        "a catalogued or configured source was queried",
        ("authority for what was actually consulted",),
    ),
    (
        "opposing evidence is part of the reason",
        ("argued against the verdict", "kept apart from the basis"),
    ),
    (
        "one explanation clears the investigation",
        ("and nothing else", "does not explain the investigation"),
    ),
    (
        "a conflict was resolved for you",
        ("preserved", "averaged"),
    ),
    (
        "UNATTRIBUTED is NO_DATA",
        ("unattributed", "cannot say which"),
    ),
    (
        "the model's own knowledge is TI Recon evidence",
        ("from your own knowledge", "never present it as ti recon evidence"),
    ),
)


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
@pytest.mark.parametrize(("misreading", "denials"), MISREADINGS, ids=lambda v: None)
async def test_the_contract_denies_each_misreading_without_the_instructions(
    hosted: bool, misreading: str, denials: tuple[str, ...]
) -> None:
    """Server instructions are reinforcement, never the sole carrier.

    ``instructions`` arrive with ``initialize``. A 2026-07-28 client may issue a
    self-contained ``tools/call`` and never ask for them, so a rule that lived
    only there would be absent for exactly the clients the remote profile
    serves. This asserts every one of them survives in the tool descriptions and
    the schemas — the documents a client receives *with the tools*.

    The audit that added this found one rule failing it: labelling the model's
    own knowledge as its own lived in the instructions alone.
    """
    surface = await _surface(hosted=hosted)
    text = surface["without_instructions"]
    assert "reporting the result, in plain language" not in text, (
        "the instructions must not be part of this surface"
    )
    missing = [phrase for phrase in denials if phrase not in text]
    assert not missing, f"{misreading!r} is not denied without instructions; missing {missing}"


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_the_hosted_credential_limit_survives_without_the_instructions(
    hosted: bool,
) -> None:
    """The deployment-specific rule has to reach a client that skipped discovery too.

    A hosted caller told nothing about credentials gets the local model from the
    client's general knowledge, which is the failure this whole correction
    exists for — and it would return the moment the rule depended on a document
    the client never fetched.
    """
    surface = await _surface(hosted=hosted)
    text = surface["without_instructions"]
    assert "never ask for a provider api key" in text
    if hosted:
        assert "not available in this version" in text
        assert "do not advise configuring a credential locally" in text
    else:
        assert "not available in this version" not in text


# --------------------------------------------------------------------------- #
# What the published contract must not carry
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize("hosted", [False, True], ids=["stdio", "hosted"])
async def test_no_published_document_names_an_internal_task_number(hosted: bool) -> None:
    """ "Task 17" means nothing to a client, and this contract is what they get.

    Pydantic publishes a model's class docstring as the schema ``description``,
    so prose written for repository readers travels to every MCP client. The
    roadmap numbering is the clearest case: an integrator reading
    "Task 17's conclusion" learns nothing and is invited to go looking for a
    Task 17 they cannot see.

    The explanations themselves stay — only the internal label goes. What each
    layer decides is exactly what a reader needs; which numbered task decided it
    is not.
    """
    surface = await _surface(hosted=hosted)
    documents = [surface["without_instructions"], surface["instructions"]]
    for tool in surface["tools"].values():
        if tool.output_schema is not None:
            documents.append(json.dumps(tool.output_schema))
        documents.append(json.dumps(tool.input_schema))

    offenders = [
        match.group()
        for document in documents
        for match in re.finditer(r"task \d+", document, re.IGNORECASE)
    ]
    assert offenders == [], f"internal task numbers reach the published contract: {offenders}"


def test_the_schema_resources_name_no_internal_task_number() -> None:
    """The same rule for the two documents served as resources.

    A consumer integrating against TI Recon validates against these, and may
    well paste them into their own documentation.
    """
    from ti_recon.reporting.schema import request_json_schema

    for label, document in (("report", report_schema()), ("request", request_json_schema())):
        rendered = json.dumps(document)
        assert not re.search(r"task \d+", rendered, re.IGNORECASE), label


def test_the_schema_descriptions_are_distinct_and_bounded() -> None:
    """Descriptions are contract, and contract that repeats itself is padding.

    Every one of them is carried in ``tools/list`` for the life of a
    conversation, so a duplicated paragraph is a cost paid on every request. A
    cap is asserted rather than a total, because the right total is whatever the
    distinctions actually need.
    """
    collected: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            described = node.get("description")
            if isinstance(described, str):
                collected.append(described)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(report_schema())
    assert collected, "the report schema must carry field descriptions"
    assert len(collected) == len(set(collected)), "a description is duplicated"
    longest = max(collected, key=len)
    assert len(longest.encode()) < 800, f"a description grew past a paragraph: {longest[:120]!r}"

"""The runtime an installed command actually gets (Task 20).

The application boundary is only useful if the thing behind it is the real
engine. These tests build the *default* application — the same function a CLI
and a future MCP server call — and prove three things about it: it registers
every provider the repository ships, it reaches a real adapter through Task 13
and Task 6 rather than around them, and it contacts nothing until an
investigation selects a provider.

Interception is a fake *client* inside the real adapter, which is the seam the
provider suites already use. Faking the adapter would prove only that a fake can
be called; faking the transport underneath the real adapter proves the public
runtime reaches the real provider architecture.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from fixtures.abusech.fake_clients import ClientFactory, FakeUrlhausClient
from ti_recon.application import AnalystInvestigationRequest, InvestigationApplication
from ti_recon.application.composition import (
    CREDENTIAL_ENVIRONMENT,
    build_default_application,
    load_environment_credentials,
)
from ti_recon.cli.runtime import LOCAL_CLI_USER, build_local_context
from ti_recon.credentials import (
    CredentialManager,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.enums import ProviderRunStatus
from ti_recon.planning.catalog import PLANNING_PROFILE_BUILDERS
from ti_recon.providers.catalog import build_default_adapters
from ti_recon.providers.urlhaus import UrlhausAdapter

#: Unmistakable, so a match in any output cannot be a coincidence.
FAKE_ABUSE_KEY = "SUPER_SECRET_ABUSE_KEY_456"
FAKE_VT_KEY = "SUPER_SECRET_VT_KEY_123"

MALICIOUS_URL = "http://malware.example/payload.bin"


# --------------------------------------------------------------------------- #
# One catalogue
# --------------------------------------------------------------------------- #


def test_every_shipped_provider_is_registered() -> None:
    """The adapter catalogue and the planning catalogue name the same providers.

    Two lists that could disagree would mean either a provider nobody can plan
    or a profile for an adapter nobody registered — and the first would look
    exactly like a capability the repository does not implement.
    """
    adapters = {item.descriptor.provider_id for item in build_default_adapters()}
    plannable = {builder().provider_id for builder in PLANNING_PROFILE_BUILDERS}

    assert adapters == plannable
    assert len(adapters) == len(build_default_adapters())


def test_building_the_catalogue_contacts_nothing() -> None:
    """Adapters create their clients lazily.

    The suite's socket and resolver guards are active, so a construction that
    opened anything would fail here rather than in production.
    """
    adapters = build_default_adapters()

    assert adapters
    assert all(item.descriptor.provider_id for item in adapters)


@pytest.mark.asyncio
async def test_the_default_application_builds_without_any_credential() -> None:
    """A fresh install starts. It does not fail, and it does not go quiet.

    Every provider stays registered whether or not a key exists, because
    ``NOT_CONFIGURED`` and "no such source" are different answers and Task 18
    decides materiality from the difference.
    """
    application, report = await build_default_application(user_id=LOCAL_CLI_USER, environment={})

    assert isinstance(application, InvestigationApplication)
    assert report.configured_groups == frozenset()


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_one_shared_key_configures_every_member_of_its_group() -> None:
    """One abuse.ch key, three adapters — the repository's own model.

    The connection repository refuses a second connection for a group a user
    already has, and the resolver looks a credential up *by group*. Storing one
    per provider would both fail and duplicate the secret.
    """
    secrets, connections = InMemorySecretStore(), InMemoryConnectionRepository()
    manager = CredentialManager(secrets, connections)

    report = await load_environment_credentials(
        manager,
        user_id=LOCAL_CLI_USER,
        adapters=build_default_adapters(),
        environment={"ABUSECH_AUTH_KEY": FAKE_ABUSE_KEY},
    )

    assert report.configured("abuse_ch")
    stored = await connections.find_by_group(LOCAL_CLI_USER, "abuse_ch")
    assert stored is not None
    # Stored once, and the connection carries a reference rather than a secret.
    assert FAKE_ABUSE_KEY not in stored.model_dump_json()


@pytest.mark.asyncio
async def test_partial_configuration_leaves_everything_else_alone() -> None:
    """Two groups configured, the rest not, and the application still starts."""
    _, report = await build_default_application(
        user_id=LOCAL_CLI_USER,
        environment={"ABUSECH_AUTH_KEY": FAKE_ABUSE_KEY, "VIRUSTOTAL_API_KEY": FAKE_VT_KEY},
    )

    assert report.configured("abuse_ch")
    assert report.configured("virustotal")
    assert not report.configured("urlscan")
    assert not report.configured("censys")


def test_every_credentialled_group_has_a_documented_variable() -> None:
    """No provider is unreachable because nobody wrote down how to configure it.

    The names are the ones ``.env.example`` already documents; this asserts the
    mapping covers every group the shipped adapters actually draw from.
    """
    groups = {
        item.descriptor.credential_group
        for item in build_default_adapters()
        if item.descriptor.requires_credentials
    }

    assert groups <= set(CREDENTIAL_ENVIRONMENT)

    documented = Path(".env.example").read_text(encoding="utf-8")
    for variable in CREDENTIAL_ENVIRONMENT.values():
        assert variable in documented, variable


# --------------------------------------------------------------------------- #
# A real adapter, reached the real way
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_public_runtime_reaches_a_real_provider_adapter() -> None:
    """Task 20 -> Task 19 -> Task 13 -> Task 6 -> the real URLhaus adapter.

    The adapter, its normalizer, its policy and its credential handling are all
    the shipped ones; only the HTTP client underneath is a fake. So this proves
    the installed application reaches the real provider architecture rather
    than a test double standing in for it — and that Task 20 never calls the
    adapter itself, since the evidence arrives through Task 6's outcome.
    """
    client = FakeUrlhausClient()
    adapter = UrlhausAdapter(client_factory=ClientFactory(client))
    application, report = await build_default_application(
        user_id=LOCAL_CLI_USER,
        adapters=[adapter],
        environment={"ABUSECH_AUTH_KEY": FAKE_ABUSE_KEY},
    )
    assert report.configured("abuse_ch")

    analyst_report = await application.investigate(
        AnalystInvestigationRequest(observable=MALICIOUS_URL), build_local_context()
    )

    # The real adapter was executed, with the real credential resolved for it.
    assert client.calls, "the shipped adapter never reached its client"
    checks = {item.provider_id: item for item in analyst_report.source_checks.items}
    assert "urlhaus" in checks
    assert checks["urlhaus"].status != ProviderRunStatus.NOT_CONFIGURED.value
    # And the fake key is nowhere in what an analyst or a tool receives.
    assert FAKE_ABUSE_KEY not in analyst_report.model_dump_json()


@pytest.mark.asyncio
async def test_several_configured_providers_leave_selection_to_task_13() -> None:
    """Task 20 registers; Task 13 chooses.

    The application hands the planner a catalogue and never expresses a
    preference — which is why the assertion is about *what ran*, decided by
    ranking, rather than about an order this layer imposed.
    """
    client = FakeUrlhausClient()
    adapters = [
        UrlhausAdapter(client_factory=ClientFactory(client)),
        *[
            item
            for item in build_default_adapters()
            if item.descriptor.provider_id in {"misp_warninglists", "threatfox"}
        ],
    ]
    application, _ = await build_default_application(
        user_id=LOCAL_CLI_USER,
        adapters=adapters,
        environment={"ABUSECH_AUTH_KEY": FAKE_ABUSE_KEY},
    )

    analyst_report = await application.investigate(
        AnalystInvestigationRequest(observable=MALICIOUS_URL), build_local_context()
    )

    consulted = {item.provider_id for item in analyst_report.source_checks.items}
    # More than one source was reachable, and the planner picked among them.
    assert consulted
    assert consulted <= {"urlhaus", "threatfox", "misp_warninglists"}


@pytest.mark.asyncio
async def test_no_secret_survives_a_real_intercepted_run() -> None:
    """Through the real runtime, not a handcrafted report.

    Both renderings and the full internal result are searched: a leak in the
    engine that the report happened not to copy would still be a leak the next
    field addition exposes.
    """
    from ti_recon.reporting import render_text

    client = FakeUrlhausClient()
    application, _ = await build_default_application(
        user_id=LOCAL_CLI_USER,
        adapters=[UrlhausAdapter(client_factory=ClientFactory(client))],
        environment={"ABUSECH_AUTH_KEY": FAKE_ABUSE_KEY, "VIRUSTOTAL_API_KEY": FAKE_VT_KEY},
    )
    request = AnalystInvestigationRequest(observable=MALICIOUS_URL)

    result = await application.run(request, build_local_context())
    analyst_report = await application.investigate(request, build_local_context())

    for haystack in (
        result.model_dump_json(),
        analyst_report.model_dump_json(),
        render_text(analyst_report),
    ):
        for secret in (FAKE_ABUSE_KEY, FAKE_VT_KEY):
            assert secret not in haystack, secret


# --------------------------------------------------------------------------- #
# Selection stays where it belongs
# --------------------------------------------------------------------------- #


def test_no_interface_module_prefers_a_provider() -> None:
    """Composition may name providers; nothing else may reason about them.

    ``providers/catalog.py`` and ``application/composition.py`` are composition
    roots, exactly like ``planning/catalog.py``. Everywhere else, a provider
    name in a conditional would be interface code overriding Task 13's ranking.
    """
    roots = {"catalog.py", "composition.py"}
    for package in (Path("src/ti_recon/application"), Path("src/ti_recon/cli")):
        for path in sorted(package.rglob("*.py")):
            if path.name in roots:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Compare):
                    rendered = ast.unparse(node)
                    assert "provider_id ==" not in rendered, f"{path.name}: {rendered}"


def test_the_providers_diagnostic_describes_the_runtime_catalogue() -> None:
    """One list, so a provider reported configured is genuinely available.

    Two lists — one to display, one to execute — would eventually disagree, and
    the disagreement would look like a provider that silently never ran.
    """
    import io

    from ti_recon.cli import run

    stdout = io.StringIO()
    assert run(["providers"], stdout=stdout, stderr=io.StringIO()) == 0

    listed = {row["provider_id"] for row in json.loads(stdout.getvalue())["providers"]}
    assert listed == {item.descriptor.provider_id for item in build_default_adapters()}

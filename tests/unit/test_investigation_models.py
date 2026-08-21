"""Investigation and ProviderRun invariants (Task 3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from ti_recon.enums import (
    ActivityMode,
    InvestigationDepth,
    InvestigationStatus,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models import Investigation, ProviderRun
from ti_recon.versions import ENGINE_VERSION, POLICY_VERSION

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)


def make_investigation(**overrides: object) -> Investigation:
    kwargs: dict[str, object] = {
        "primary_object_id": "obj-1",
        "original_input": "evil.example",
        "engine_version": ENGINE_VERSION,
        "policy_version": POLICY_VERSION,
    }
    kwargs.update(overrides)
    return Investigation(**kwargs)  # type: ignore[arg-type]


def make_run(**overrides: object) -> ProviderRun:
    kwargs: dict[str, object] = {
        "investigation_id": "inv-1",
        "provider": "fake_provider",
        "capability": ProviderCapability.REPUTATION,
        "operation": ProviderOperation.LOOKUP,
        "status": ProviderRunStatus.SUCCESS,
    }
    kwargs.update(overrides)
    return ProviderRun(**kwargs)  # type: ignore[arg-type]


def test_investigation_defaults_are_passive_and_standard() -> None:
    investigation = make_investigation()
    assert investigation.activity_mode is ActivityMode.PASSIVE
    assert investigation.depth is InvestigationDepth.STANDARD
    assert investigation.status is InvestigationStatus.PENDING
    assert investigation.completed_at is None


def test_investigation_capabilities_are_deduplicated_and_ordered() -> None:
    investigation = make_investigation(
        requested_capabilities=[
            ProviderCapability.SCANNER_CONTEXT,
            ProviderCapability.REPUTATION,
            ProviderCapability.SCANNER_CONTEXT,
        ]
    )
    assert investigation.requested_capabilities == [
        ProviderCapability.REPUTATION,
        ProviderCapability.SCANNER_CONTEXT,
    ]


def test_investigation_rejects_completion_before_start() -> None:
    with pytest.raises(ValidationError, match="must not precede started_at"):
        make_investigation(started_at=T0, completed_at=T0 - timedelta(seconds=1))


def test_investigation_has_no_claude_or_mcp_fields() -> None:
    """The core engine must remain independent of Claude and MCP."""
    field_names = " ".join(Investigation.model_fields).lower()
    for forbidden in ("claude", "mcp", "prompt", "skill", "llm", "model_name"):
        assert forbidden not in field_names


def test_provider_run_records_versions_for_auditability() -> None:
    run = make_run(api_version="v3", adapter_version="0.1.0")
    assert run.api_version == "v3"
    assert run.adapter_version == "0.1.0"


def test_provider_run_duration() -> None:
    run = make_run(started_at=T0, completed_at=T0 + timedelta(milliseconds=1500))
    assert run.duration_seconds == 1.5
    assert make_run().duration_seconds is None


def test_successful_run_must_not_carry_an_error_code() -> None:
    with pytest.raises(ValidationError, match="must not carry an error_code"):
        make_run(
            status=ProviderRunStatus.SUCCESS,
            error_code=ProviderErrorCategory.RATE_LIMITED,
        )


def test_failed_run_must_carry_an_error_code() -> None:
    with pytest.raises(ValidationError, match="normalized error_code"):
        make_run(status=ProviderRunStatus.ERROR)


def test_non_error_statuses_do_not_require_an_error_code() -> None:
    for status in (
        ProviderRunStatus.NO_DATA,
        ProviderRunStatus.NOT_CONFIGURED,
        ProviderRunStatus.NOT_SUPPORTED,
        ProviderRunStatus.PLAN_LIMITED,
        ProviderRunStatus.QUOTA_EXCEEDED,
        ProviderRunStatus.PARTIAL,
        ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
    ):
        assert make_run(status=status).status is status


def test_cache_hit_defaults_to_false() -> None:
    assert make_run().cache_hit is False

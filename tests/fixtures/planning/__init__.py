"""Controlled fake providers for planner tests.

Most planner tests use these rather than the shipped catalogue, and that is the
point: a planner tested only against today's nine providers would be a test of
today's provider list. These fakes exist to prove the planner is generic —
two datasets in one family, two independent families, a local provider, an
expensive specialist, a provider that always fails.

A separate suite checks the real catalogue, so both properties are covered
without either test doing the other's job.
"""

from fixtures.planning.fakes import (
    EXPENSIVE_BEHAVIOR,
    FAMILY_A,
    FAMILY_B,
    LOCAL_CONTEXT,
    FakePlanningAdapter,
    FakeProviderSpec,
    build_registry,
    fake_outcome,
    file_object,
    profile_for,
    specs_for,
)

__all__ = [
    "EXPENSIVE_BEHAVIOR",
    "FAMILY_A",
    "FAMILY_B",
    "LOCAL_CONTEXT",
    "FakePlanningAdapter",
    "FakeProviderSpec",
    "build_registry",
    "fake_outcome",
    "file_object",
    "profile_for",
    "specs_for",
]

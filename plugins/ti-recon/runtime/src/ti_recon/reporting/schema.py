"""The machine-readable form of the analyst contract (Task 20).

Generated from the models rather than hand-written, so the published schema and
the objects an application receives cannot drift apart. A second, maintained-by-
hand schema is a promise that stops being true the first time somebody adds a
field and forgets.

The dialect is read from Pydantic rather than asserted, because claiming a
dialect the generator does not actually emit would be worse than saying nothing:
a consumer's validator would be configured for a spec the document does not
follow.
"""

from __future__ import annotations

from typing import Any

from pydantic.json_schema import GenerateJsonSchema

from ti_recon.reporting.models import AnalystInvestigationReport

__all__ = ["SCHEMA_DIALECT", "report_json_schema", "request_json_schema", "schema_for"]

#: The JSON Schema dialect the installed Pydantic emits, taken from Pydantic.
SCHEMA_DIALECT: str = GenerateJsonSchema.schema_dialect


def schema_for(model: type[Any], *, title: str) -> dict[str, Any]:
    """One model's schema, with the dialect stated explicitly.

    Pydantic omits ``$schema`` by default; a published contract should carry it
    so a validator knows which specification to apply.
    """
    schema = dict(model.model_json_schema())
    schema["$schema"] = SCHEMA_DIALECT
    schema["title"] = title
    return schema


def report_json_schema() -> dict[str, Any]:
    """The schema an application validates a report against."""
    return schema_for(AnalystInvestigationReport, title="AnalystInvestigationReport")


def request_json_schema() -> dict[str, Any]:
    """The schema an application builds a request against."""
    from ti_recon.application.models import AnalystInvestigationRequest

    return schema_for(AnalystInvestigationRequest, title="AnalystInvestigationRequest")

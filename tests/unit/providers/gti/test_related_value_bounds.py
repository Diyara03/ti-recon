"""A related value the model cannot hold costs one object, never the lookup (Task 24 Phase 3).

A 5000-character contacted URL from GTI used to raise the Task 3 model's own
validation error out of ``lookup``, which Task 6 recorded as a schema error --
the reputation and sandbox evidence beside it were lost. The value is now
counted unresolved and everything else survives.
"""

from __future__ import annotations

from fixtures.gti import payloads
from fixtures.gti.fake_client import FakeGTIClient
from ti_recon.enums import InvestigationDepth, ProviderRunStatus

from .test_threat_context import SHA256, credential, file_subject, make_adapter, request_for

LONG_URL = "https://example.test/" + "a" * 5000


async def test_an_over_long_related_url_is_dropped_and_the_lookup_survives() -> None:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    fake.register_objects(
        "files",
        SHA256,
        "contacted_urls",
        payloads.object_page(
            {"type": "url", "id": "u-long", "attributes": {"url": LONG_URL}},
            {"type": "url", "id": "u-short", "attributes": {"url": "https://example.test/ok"}},
        ),
    )
    adapter = make_adapter(fake)

    outcome = await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )

    assert outcome.status in {ProviderRunStatus.SUCCESS, ProviderRunStatus.PARTIAL}
    values = {item.canonical_value for item in outcome.objects}
    assert "https://example.test/ok" in values
    assert LONG_URL not in values
    assert any(item.claim_type == "gti_assessment" for item in outcome.evidence)

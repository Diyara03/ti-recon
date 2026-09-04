"""A ThreatFox claim says which IOC matched and how (Task 24 Phase 2).

A bare address is searched loosely and matches an ``ip:port`` record on its
host component at ``SAME_IP`` scope. The scope already keeps "port 443 was a
C2" from reading as "this address is a C2"; the highlights let a report say
so in the provider's own terms -- the IOC, the component that matched, the
port, the threat type and the family -- without changing what the claim is.
"""

from __future__ import annotations

from fixtures.reasoning import threatfox_ip_envelope
from ti_recon.enums import MatchScope
from ti_recon.reasoning.claims import (
    CLAIM_SEMANTICS_POLICY_VERSION,
    ClaimTranslationContext,
    translate_envelope,
)


def test_a_port_qualified_match_is_quoted_as_the_ioc_it_matched() -> None:
    envelope = threatfox_ip_envelope()
    context = ClaimTranslationContext.build(
        objects=envelope.objects, policy_version=CLAIM_SEMANTICS_POLICY_VERSION
    )
    claims = [
        item for item in translate_envelope(envelope, context) if item.scope is MatchScope.SAME_IP
    ]
    assert claims, "the fixture's ip:port record should match the address at SAME_IP"
    highlights = claims[0].highlights
    assert any(item.startswith("ioc: ") and ":" in item.split("ioc: ", 1)[1] for item in highlights)
    assert "matched_component: host" in highlights
    assert any(item.startswith("port: ") for item in highlights)
    assert any(item.startswith("threat_type: ") for item in highlights)
    assert len(highlights) <= 8
    # The contributor's confidence stays provider data: never on the claim.
    assert not any("confidence" in item for item in highlights)

# Provider-Neutral Claim Semantics

> Task 17A. What each piece of evidence actually asserts, in vocabulary no
> vendor owns. Implemented in `src/ti_recon/reasoning/claims/`.

## 1. The problem Task 16 named

Task 16 found a wall and described it precisely:

```
GreyNoise scanner classification -> EvidenceClass.CURATED_THREAT_ASSERTION, SUPPORTS_MALICIOUS
ThreatFox botnet-C2 indicator    -> EvidenceClass.CURATED_THREAT_ASSERTION, SUPPORTS_MALICIOUS
```

Two completely different accusations about the same address, indistinguishable to
a generic layer. The only field separating them was `claim_type` — and every
`claim_type` in this repository is provider-prefixed, so reading one would put a
vendor name in the reasoning core.

Task 16 therefore *deferred* its scanner rule rather than guess. This layer is the
seam that removes the guess.

## 2. The pipeline

```
provider raw response
      ↓  (Tasks 7-12 normalizers)
Evidence — authoritative, untouched
      ↓  (provider-owned claim_semantics.py)
NormalizedClaim — a proposition, in generic vocabulary
      ↓
ClaimPropositionKey — subject + semantic + scope
      ↓
independence / corroboration
      ↓
fusion
```

A claim is a **view** over evidence. It references the evidence by id, copies the
provenance fusion needs, and copies no payload. Evidence stays authoritative and
unaware this layer exists.

## 3. Semantic is not verdict

This distinction is the reason the layer is safe:

| Concept | Answers |
|---|---|
| `ClaimSemantic` | *What* is being asserted — the dimension |
| `EvidenceEffect` | *Which way* it points — the direction |
| Fusion policy | *What it is worth* — the decision |

`C2_ASSOCIATION` says a source claims this address served command and control. It
does not say the investigation is malicious. `SCANNER_ACTIVITY` says a sensor
network classified the address's scanning behaviour — which is not benign either.

## 4. The vocabulary

Twelve semantics, each backed by structure a shipped provider already normalizes.
It is not a CTI ontology; it is the smallest set of distinctions the current data
can honestly draw.

| Semantic | Meaning |
|---|---|
| `MALWARE_SAMPLE_IDENTITY` | A curated repository holds this exact file as a known sample |
| `MALWARE_DISTRIBUTION` | This artifact served or delivered malware |
| `C2_ASSOCIATION` | This address or name served command and control |
| `THREAT_INFRASTRUCTURE_ASSOCIATION` | Tied to malicious infrastructure, role unstated |
| `THREAT_ACTOR_ASSOCIATION` | Associated with a named actor, campaign or report |
| `SCANNER_ACTIVITY` | A sensor network classified its internet-scanning behaviour |
| `SANDBOX_CLASSIFICATION` | A sandbox reached a verdict about what it did when run |
| `MALICIOUS_REPUTATION` | A provider's own curated malicious verdict |
| `BENIGN_REPUTATION` | A provider's own curated benign verdict |
| `AGGREGATED_REPUTATION` | A roll-up of other parties' opinions |
| `UNCLASSIFIED_DIRECTIONAL` | Directional, and nobody could say what it asserts |

`ClaimAssertionStrength` carries the hedge providers actually state —
`ASSERTED` versus `SUSPECTED`. Task 12 preserved a sandbox's `suspicious` verdict
separately from `malicious` and GTI has `VERDICT_SUSPICIOUS`; flattening both into
one direction would throw that away, so the distinction rides here rather than
doubling the semantic vocabulary. A suspected claim is never decisive.

### Qualification (Task 24 Phase 1B)

Beside its strength a claim carries a **`qualification`** —
`ClaimQualification.UNQUALIFIED`, `STRONG_DIRECT` or `NOT_STRONG` — with
bounded stable reason codes. It answers a question strength does not: not
*how firmly* the source states the claim, but *how much stands behind it*, by
the source's own documented record. Only a provider translator may set it,
under its own versioned test over its own fields (today: GTI's sandbox
consensus, `docs/providers/gti.md` §7a). Fusion reads the enum alone and lets
`STRONG_DIRECT` promote a sandbox classification to decisive; `NOT_STRONG` is
weighed exactly like `UNQUALIFIED`. Neither a count nor a confidence ever
crosses into the generic layer, and no provider is named there.

## 5. Provider mapping

Every translator lives in its own provider package and reads only its own
structured fields.

| Provider | Claim | Semantic |
|---|---|---|
| MalwareBazaar | `malwarebazaar_sample_record` | `MALWARE_SAMPLE_IDENTITY` |
| URLhaus | `urlhaus_malware_url` | `MALWARE_DISTRIBUTION` |
| URLhaus | `urlhaus_host_malware_association` | `THREAT_INFRASTRUCTURE_ASSOCIATION` |
| URLhaus | `urlhaus_payload_record` | `THREAT_INFRASTRUCTURE_ASSOCIATION` |
| ThreatFox | `threatfox_ioc`, `threat_type=botnet_cc` | `C2_ASSOCIATION` |
| ThreatFox | `threatfox_ioc`, `threat_type=payload_delivery`/`payload` | `MALWARE_DISTRIBUTION` |
| ThreatFox | `threatfox_ioc`, any other threat type | `THREAT_INFRASTRUCTURE_ASSOCIATION` |
| ThreatFox | `threatfox_hash_association` | `THREAT_INFRASTRUCTURE_ASSOCIATION` |
| GreyNoise | `greynoise_classification` | `SCANNER_ACTIVITY` |
| GTI | `gti_assessment`, `VERDICT_MALICIOUS` | `MALICIOUS_REPUTATION` |
| GTI | `gti_assessment`, `VERDICT_SUSPICIOUS` | `MALICIOUS_REPUTATION` (suspected) |
| GTI | `gti_assessment`, `VERDICT_BENIGN` | `BENIGN_REPUTATION` |
| GTI | `gti_analysis_stats` | `AGGREGATED_REPUTATION` |
| GTI | `gti.threat_actor_association` and siblings | `THREAT_ACTOR_ASSOCIATION` |
| GTI | `gti.sandbox_verdict.malicious` | `SANDBOX_CLASSIFICATION` |
| GTI | `gti.sandbox_verdicts`, verdict `malicious` / `suspicious` | `SANDBOX_CLASSIFICATION` (asserted / suspected), qualified by the consensus test |
| GTI | `gti.behavior.verdict`, verdict `asserted` / `suspected` | `SANDBOX_CLASSIFICATION` (asserted / suspected) |
| GTI | `gti.threat_association.malware-families`, `.related-threat-actors`, `.campaigns` | `THREAT_ACTOR_ASSOCIATION` |
| GTI | `gti.threat_association.related-reports`, `.associations` | `THREAT_ACTOR_ASSOCIATION` (suspected) |
| GTI | `gti.analyst_determination.*`, `gti.legitimate_software` | `MALICIOUS_`/`BENIGN_REPUTATION` |
| urlscan | `urlscan_verdict` | `MALICIOUS_REPUTATION` |
| urlscan | `urlscan_engine_aggregate`, `urlscan_community_votes` | `AGGREGATED_REPUTATION` |
| Hybrid Analysis | `hybrid_analysis_sandbox_assessment` | `SANDBOX_CLASSIFICATION` |
| Censys | — | none; exposure is not an accusation |
| MISP Warning Lists | — | none; a warninglist hit is context |

ThreatFox's `threat_type` is a documented platform value, not prose — which is
what makes the scanner/C2 distinction possible at all. GTI's contributing factors
are a closed table in Task 7, so the translator keys on exact claim types and a
factor added later produces no claim until somebody adds a row.

## 6. Coverage is enforced

A regression test drives the **real adapters** over the real fixtures and asserts:

* one claim out per directional finding in — nothing disappears;
* no shipped provider currently produces `UNCLASSIFIED_DIRECTIONAL`;
* context-only evidence never becomes a claim.

A provider adding a directional claim type therefore fails CI until somebody makes
an intentional decision. `UNCLASSIFIED_DIRECTIONAL` remains the honest fallback for
a provider with no translator: its findings stay visible and can never be decisive.

## 7. Compatibility is explicit and versioned

Two claims corroborate only when their semantics are *compatible*, stated in a
table rather than inferred from names:

```python
COMPATIBLE_SEMANTICS = {
    {MALWARE_SAMPLE_IDENTITY, SANDBOX_CLASSIFICATION},
    {MALICIOUS_REPUTATION, SANDBOX_CLASSIFICATION},
}
NON_CORROBORATING_SEMANTICS = {AGGREGATED_REPUTATION, UNCLASSIFIED_DIRECTIONAL}
```

Everything else corroborates only itself. In particular:

* **`SCANNER_ACTIVITY` is compatible with nothing but scanner activity.** That is
  the entire point of naming it. A test walks every other semantic to prove it.
* **`AGGREGATED_REPUTATION` is compatible with nothing, itself included.** One
  source relaying forty opinions is one source; two aggregates corroborating would
  be vendor counting with an extra step.

`CLAIM_SEMANTICS_POLICY_VERSION` is folded into every claim id, so a translation
change produces different claims rather than silently reinterpreting stored ones.
It is `1.2.0` as of Task 24 Phase 1B (`1.1.0` added the GTI rows above;
`1.2.0` added the claim qualification and the GTI consensus test).

A claim may carry bounded **`highlights`** (Task 24): at most eight lines of at
most 160 characters, built from named attributes only — the source's own words
about its own claim, for the report to quote. They are presentation: fusion
never reads them, and a claim without any weighs exactly the same.

See [evidence-fusion.md](evidence-fusion.md) for what fusion does with these.

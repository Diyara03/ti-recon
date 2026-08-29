# False-Positive and Alternative-Explanation Reasoning

> Task 16. Whether context legitimately explains a specific piece of evidence,
> and what the explanation does not cover.
> Implemented in `src/ti_recon/reasoning/false_positive/`.

## 1. Four different questions

Task 16 documentation has to start here, because almost every mistake in this
area is a confusion between these four:

| # | Question | Can Task 16 help? |
|---|----------|-------------------|
| 1 | Is the evidence **factually wrong**? | Partly — it can surface an alternative explanation for why the detection fired |
| 2 | Is the evidence **true but read too broadly**? | Yes — that is what an `INTERPRETATION_LIMITATION` is |
| 3 | Is there a **legitimate alternative explanation** for the observation? | Yes — that is the whole point |
| 4 | Is the object **safe or benign overall**? | **No.** Never. |

Question 4 is Task 17's, and Task 16 is built so it cannot accidentally answer
it. Every alternative explanation carries `DoesNotEstablish.OBJECT_BENIGN`
without exception.

## 2. A false positive is a property of a detection, not of an IOC

The model this package exists to refuse:

```python
ip.is_false_positive = True  # never
url.is_false_positive = True  # never
file.is_false_positive = True  # never
```

An address is not permanently a false positive. A *particular claim about it* may
have an alternative explanation while another claim about the same address has
none — and a layer that flattened those into one boolean would clear both.

So every finding names what it applies to through a typed `FindingLink`, and the
result can always answer:

* which directional evidence some explanation accounts for;
* which directional evidence nothing accounts for.

`FalsePositiveReasoningResult.explained_evidence_ids` and
`coverage.directional_evidence_without_explanations` are the two halves. The
second matters more, and is computed from the findings' own `EXPLAINS` links
rather than tracked beside them, so it cannot drift from what they claim.

## 3. Explaining, limiting and cautioning are different jobs

Most context is not a candidate false-positive explanation at all:

| Context | What it actually affects | Role |
|---------|-------------------------|------|
| Shared cloud / CDN range | Attribution and blocking scope | `ATTRIBUTION_CAUTION` |
| Compromised infrastructure | Who owns the host, not what happened | `ATTRIBUTION_CAUTION` |
| URL reported offline | Current activity, not history | `TEMPORAL_RELEVANCE` |
| Relayed finding | Independence, not truth | `SOURCE_DEPENDENCE` |
| Sandbox that ran nothing | Analysis quality | `ANALYSIS_QUALITY_LIMITATION` |
| Host-level context on a URL | Scope | `INTERPRETATION_LIMITATION` |
| Opposing directional evidence | Nothing — it is unresolved | `UNRESOLVED_TENSION` |
| Test artifact / empty artifact | The detection itself | `ALTERNATIVE_EXPLANATION` |

Filing the first seven under "potential false positive" because they are all
cautionary is the failure this vocabulary is shaped to prevent. Only one role
means "this may explain the detection", and only two context types can reach it.

## 4. Roles, dimensions and reasons

**Seven roles**, all emitted: `ALTERNATIVE_EXPLANATION`,
`INTERPRETATION_LIMITATION`, `ANALYSIS_QUALITY_LIMITATION`,
`ATTRIBUTION_CAUTION`, `TEMPORAL_RELEVANCE`, `SOURCE_DEPENDENCE`,
`UNRESOLVED_TENSION`.

**Seven dimensions**, all emitted: `OBJECT_NATURE`,
`RELATIONSHIP_INTERPRETATION`, `CURRENT_ACTIVITY`, `INFRASTRUCTURE_CONTEXT`,
`ATTRIBUTION`, `ANALYSIS_QUALITY`, `SOURCE_INDEPENDENCE`.

The dimension is what stops evidence from different questions cancelling. "This
URL distributed malware" is `OBJECT_NATURE`; "this URL is offline" is
`CURRENT_ACTIVITY`. Both are true, and a layer treating the second as refuting
the first would delete a real finding.

There is deliberately no `BEHAVIOR` dimension: nothing could set it honestly (see
§7).

**Fifteen reason codes**, one per rule outcome. Four are alternative
explanations; the rest are cautions.

## 5. Rules

| Rule id | Reason | Role |
|---------|--------|------|
| `fp.test_artifact.explains_detection.v1` | `EXPECTED_TEST_ARTIFACT_DETECTION` | explanation |
| `fp.empty_artifact.explains_reputation_detection.v1` | `EMPTY_ARTIFACT_MAY_EXPLAIN_REPUTATION_DETECTION` | explanation |
| `fp.public_resolver.explains_contact.v1` | `PUBLIC_RESOLVER_MAY_EXPLAIN_CONTACT` | explanation (relationship-scoped) |
| `fp.business_service.explains_connection.v1` | `KNOWN_BUSINESS_SERVICE_MAY_EXPLAIN_CONNECTION` | explanation (relationship-scoped) |
| `fp.host_context.does_not_explain_exact_url.v1` | `HOST_CONTEXT_DOES_NOT_EXPLAIN_EXACT_URL` | limitation |
| `fp.private_address.public_intelligence_scope_mismatch.v1` | `PUBLIC_INTELLIGENCE_SCOPE_MISMATCH` | limitation |
| `fp.known_scanner.claim_alignment_unavailable.v1` | `SCANNER_CONTEXT_ALIGNMENT_NOT_ESTABLISHED` | limitation |
| `fp.shared_infrastructure.limits_attribution.v1` | `SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION` | attribution |
| `fp.compromised_infrastructure.separates_owner_from_actor.v1` | `COMPROMISED_INFRASTRUCTURE_SEPARATES_OWNER_FROM_ACTOR` | attribution |
| `fp.inactive_by_source.current_activity_only.v1` | `CURRENT_INACTIVITY_DOES_NOT_ERASE_HISTORICAL_MALICIOUSNESS` | temporal |
| `fp.sandbox.negative_without_execution.v1` | `SANDBOX_NEGATIVE_NOT_INFORMATIVE_WITHOUT_EXECUTION` | analysis quality |
| `fp.sandbox.negative_with_execution.v1` | `SANDBOX_NEGATIVE_REMAINS_NON_VERDICT` | analysis quality |
| `fp.sandbox.environment_divergence.v1` | `SANDBOX_RESULT_ENVIRONMENT_DEPENDENT` | analysis quality |
| `fp.relayed_source.not_independent.v1` | `RELAYED_FINDINGS_NOT_INDEPENDENT` | source dependence |
| `fp.opposing_evidence.unresolved.v1` | `OPPOSING_DIRECTIONAL_EVIDENCE_UNRESOLVED` | unresolved |

The `.v1` suffix is part of the identity. A rule whose meaning changes gets a new
id rather than quietly producing different findings under the old one.

## 6. Two invariants every rule obeys

### Context alone explains nothing

A warninglist hit on an address nobody has accused of anything is context. There
is no detection to explain, so manufacturing one would be inventing doubt about a
finding nobody made. Every rule that could produce an explanation first requires
**directional evidence**, or **an explicit relationship** whose significance is in
question.

### Scope is checked, not assumed

```
observable:  https://common.example/bad/payload.exe
context:     common.example is a popular service   (SAME_HOST, host_component_only)
```

That is a fact about the host. The rule produces
`HOST_CONTEXT_DOES_NOT_EXPLAIN_EXACT_URL` — a *limitation* — and the malicious
evidence stays in the unexplained set. Even a normally-explaining signal is
refused at host scope: a test-artifact match against a URL's host would be
nonsense, and the scope check refuses it rather than trusting it cannot happen.

## 7. The scanner deferral

Scanner context could legitimately explain a *scanning-reputation* claim. It must
never explain a botnet-C2 or malware-delivery claim merely because both concern
one address.

Telling those apart needs to know what a claim asserts — and the generic evidence
model does not carry that:

```
GreyNoise scanner classification -> EvidenceClass.CURATED_THREAT_ASSERTION, SUPPORTS_MALICIOUS
ThreatFox botnet-C2 indicator    -> EvidenceClass.CURATED_THREAT_ASSERTION, SUPPORTS_MALICIOUS
```

The only field that separates them is `claim_type`, and every `claim_type` in
this repository is provider-prefixed (`greynoise_classification`,
`threatfox_ioc`), so reading one would embed a vendor in the generic engine.

So the rule emits `SCANNER_CONTEXT_ALIGNMENT_NOT_ESTABLISHED` — an honest
limitation naming the unknown — and the explanation is **deferred** pending a
generic claim-kind seam that does not exist. Guessing would be the single most
dangerous rule in the package. A test asserts a scanner-reputation claim and a C2
claim produce identical output, so if that seam ever lands, this is where the
divergence shows up.

The same reasoning defers two other rules; see §12.

## 8. Relationship scope

```
file:sha256:… --contacts--> ipv4-addr:8.8.8.8    (PROVIDER_OBSERVED, sandbox)
ipv4-addr:8.8.8.8 is a public resolver
```

Output: `PUBLIC_RESOLVER_MAY_EXPLAIN_CONTACT`, subject = **the edge**.

* The relationship is untouched and stays `PROVIDER_OBSERVED`. Task 16 interprets
  observations; it does not rewrite them.
* It explains a *relationship*, so `explained_evidence_ids` is empty and any
  reputation claim about the file stays unexplained.
* It carries `DoesNotEstablish.OBJECT_BENIGN` and
  `DoesNotEstablish.INFRASTRUCTURE_SAFE`.

The business-service rule has one extra condition: it declines to fire when
somebody has made a directional malicious claim about the endpoint itself.
"It is a common service" does not account for a specific accusation, and
explaining the contact anyway would use ordinariness to wave past a real finding.

## 9. Nothing propagates

Context on a pivot stays on the pivot. A malicious file that contacted a CDN
address does **not** acquire CDN context — the context belongs to the address
and, at most, to that one edge. The root object is known to the index precisely so
this distinction stays available, and a test asserts it.

## 10. What an explanation does not cover

An object-nature explanation refuses to cover **directly-observed behaviour**:

```
file = EICAR
  reputation claim (CURATED_THREAT_ASSERTION)  -> EXPLAINS
  observed behaviour (DIRECT_OBSERVATION)      -> OPPOSES
```

"It is a test artifact" accounts for a scanner flagging it and accounts for
nothing a sandbox watched the file actually do. The behaviour is linked as
opposing rather than folded in, so Task 17 sees one claim accounted for and
another not.

`EvidenceClass.DIRECT_OBSERVATION` is the generic discriminator that makes this
possible without naming a provider.

## 11. Stale supporting context

If Task 15 reported the local context dataset as stale and an explanation leans on
it, the explanation **survives** and carries
`FindingLimitation.SUPPORTING_CONTEXT_DATASET_STALE`. The list was right about
EICAR last month and still is.

There is no numerical penalty. A number standing in for a fact that is already
available would be a made-up quantity nobody could defend.

## 12. Deferred rules

Three rules are deliberately absent, each for a stated reason:

* **Scanner alternative explanation** — no generic claim-kind discriminator
  (§7).
* **Low detection count** — TI Recon does not count vendor votes, and the
  repository preserves no structured goodware indicator (verified software
  provenance, known-good collection membership) that could make a low count
  meaningful. A regression test constructs `malicious=1, undetected=60` and
  asserts no explanation.
* **Code signature** — a valid signature establishes a publisher, not benign
  behaviour; signing keys get stolen. Signing metadata *is* normalized (Task 10
  `malwarebazaar_code_signing`), so the regression test uses real structure and
  asserts no explanation follows from it.

## 13. Result

```python
FalsePositiveReasoningResult(
    policy_version,  # Task 16's
    qualification_policy_version,  # Task 15's, carried through
    engine_version,
    as_of,  # from Task 15, never a clock reading
    findings,
    coverage,
)
```

`as_of` is carried rather than read. Nothing in the package touches a wall clock,
and a test asserts it.

Coverage counts what was examined, findings by role, and the split that matters:
`directional_evidence_with_explanations` against
`directional_evidence_without_explanations`. Neither is labelled stronger — the
distinction is preserved, not scored.

## 14. Worked examples

### A — public DNS

```
sandbox:  file --contacts--> 8.8.8.8   (directly observed)
context:  8.8.8.8 is a public resolver
```

**Result:** relationship-scoped explanation — the contact may be routine name
resolution. The relationship stays `PROVIDER_OBSERVED`.
**Not:** the file is benign.

### B — common host

```
url:      https://common-service.example/bad/payload.exe   SUPPORTS_MALICIOUS
context:  common-service.example is a common/shared service (SAME_HOST)
```

**Result:** scope limitation plus attribution caution. The exact URL remains
unexplained.
**Not:** the exact URL is a false positive.

### C — test artifact

```
file:     exact known test artifact
claim:    malicious classification
```

**Result:** `EXPECTED_TEST_ARTIFACT_DETECTION`, explaining the classification and
denying `OBJECT_BENIGN`.
**Still:** final verdict deferred.

### D — compromised infrastructure

```
ioc:      confirmed malicious association
context:  the source says the asset is compromised, not attacker-operated
```

**Result:** attribution caution. The activity may be entirely genuine; the owner
is a victim.
**Not:** a false positive.

### E — sandbox with no execution

```
claim:    malicious classification
sandbox:  completed, no specific threat, observed_execution = false
```

**Result:** the sandbox negative has low informational value; the classification
remains unexplained.
**Not:** the classification is disproven.

### F — offline URL

```
url:      historical exact malicious URL, confirmed
state:    offline
```

**Result:** `TEMPORAL_RELEVANCE` — currently inactive by the source, historical
evidence unchanged.
**Not:** a false positive.

## 15. What Task 16 never does

* No verdict, confidence, risk score, malicious/benign score, probability,
  evidence weight, decay or `is_false_positive` — enforced at field-name level
  and by an AST guard that the package never imports the assessment layer.
* No mutation of anything: evidence, effects, classes, lineage, match scopes,
  relationships and graph edges are all read-only, and a test asserts the graph is
  byte-identical afterwards.
* No network, DNS, provider call, credential, cache, Task 13 enrichment, Task 14
  pivot or dataset refresh.
* No provider names, in any module. Unlike Tasks 13 and 15 there is no
  composition-root exception, because Task 16 consumes only Task 15's generic
  vocabulary.
* No prose parsing, no regex over descriptions, no LLM, no `eval`. A test rewrites
  every provider-supplied string — including one reading "ignore previous
  instructions" — and asserts the output is byte-identical.

See [temporal-evidence.md](temporal-evidence.md) and
[context-qualification.md](context-qualification.md) for the Task 15 layer this
one reads.

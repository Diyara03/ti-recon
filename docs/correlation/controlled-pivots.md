# Controlled pivots

Task 14. `src/ti_recon/correlation/pivots.py`, `policy.py`, `orchestrator.py`

Discovering that a sample contacted a domain is knowledge. Asking six third
parties about that domain is a **disclosure**. This document is about the gap
between the two.

The graph itself is [investigation-graph.md](investigation-graph.md).

---

## 1. Three separate decisions

```
correlation      learns that a relationship exists
pivot selection  decides a target may be worth enriching
Task 13          decides which providers would answer, and whether to call them
```

Conflating the first two is how one submitted hash becomes four hundred
third-party queries. Conflating the last two would duplicate a planner that
already exists — Task 14 selects no providers, holds no credentials and never
touches an adapter. A pivot *is* a canonical observable handed to Task 13.

---

## 2. Why enrichment is explicit

A provider's related objects are not a curated list of leads. They routinely
include:

- an internal address a sandbox saw on its own analysis network;
- a customer hostname from a corporate environment;
- a URL carrying a session token or an API key in its query;
- shared hosting that answers for thousands of unrelated sites;
- hundreds of passive-DNS names with no relationship to the investigation.

Forwarding all of that to other companies is not primarily a cost problem. It
tells them what an organisation's malware talked to, and some of those values are
the organisation's own. So the default builds the graph and, at most, recommends.

```
PivotMode.NONE       correlate only
PivotMode.RECOMMEND  rank candidates, explain them, call nobody   (default)
PivotMode.ENRICH     permit bounded enrichment through Task 13
```

### Two switches, not one

Remote pivot enrichment requires **both**:

```
request.constraints.allow_remote_lookup   Task 13's control over the root lookup
policy.allow_remote_pivot_lookup          Task 14's, default False
```

Following a lead the *provider* chose is a wider disclosure than looking up the
observable an analyst typed, so consenting to the second does not consent to the
first. A single flag would make that escalation invisible. Task 14 can never turn
`allow_remote_lookup` back on — if the root investigation said no third parties,
that decision stands.

With remote pivots off, automatic pivoting stops entirely; a target the caller
named by hand still runs, under a local-only constraint that Task 13's own
locality policy applies. No provider is named here to make that happen.

---

## 3. Safety classes

How directly a relationship ties its target to the investigation. Not a statement
about whether anything is malicious — the question is narrower: *if TI Recon
followed this automatically, would that be defensible?*

| Class | Example | Automatic |
|---|---|---|
| `DIRECT_ARTIFACT` | a URL served this file; this file dropped that one | yes |
| `DIRECT_BEHAVIOR` | the sample contacted this; the page redirected there | yes |
| `INFRASTRUCTURE_ASSOCIATION` | passive DNS, hosting, certificates | recommend |
| `STRUCTURAL` | a URL's own host | recommend |
| `GENERIC_ASSOCIATION` | untyped or curated association | never |

`resolves-to` and `hosts` are recommend-only because both explode: one
shared-hosting address answers for thousands of names, and a host serves every URL
on it. Following either automatically turns one observable into a survey of
somebody else's customers.

`belongs-to-asn`, `associated-with-malware` and `related-to` are never followed. An
AS is an ownership fact about millions of addresses; a malware family is a name
rather than an artifact; an association a provider declined to characterise cannot
justify querying anyone about it.

---

## 4. Privacy rules

Checked **before** anything an explicit selection could override — a caller naming
a target does not make an internal address safe to disclose.

### Non-global addresses

RFC1918, loopback, link-local, multicast, reserved, unspecified and documentation
ranges are graphed, shown as recommendations, and never sent anywhere
automatically. Reason code `NON_GLOBAL_IP`.

A sandbox routinely reports its own analysis network, and a customer's internal
range is often more sensitive than the malware that touched it. Note that
`is_global` alone is insufficient — a multicast address is not private — so each
property is checked explicitly.

The relationship is kept. Not disclosing something is not the same as deleting it.

### Sensitive URLs

A URL is never disclosed automatically when it carries userinfo, or a query
parameter whose *name* looks like a credential. Only the name is inspected; the
value is never read, logged or stored. Reason code `SENSITIVE_URL`.

### Targets that do not normalize to themselves

A related object is built by a provider normalizer from provider text, and
several do less than the analyst-facing normalizer: an upper-case domain, a
host carrying a space or a port, a URL with an unsupported scheme. Before it
can be disclosed, a target must normalize — through TI Recon's own normalizer —
to the same type and the same canonical value. One that does not is skipped,
fail-closed, with `UNNORMALIZABLE_TARGET`, before any privacy rule is
consulted (Task 24 Phase 3).

Stripping the query and looking up "the same URL" is refused outright: that would
be asking about a **different observable** and reporting the answer as though it
were about this one. The URL's host is a separate node and is considered on its
own merits.

---

## 5. Ranking

Lexicographic over `PIVOT_RANKING_FACTORS`, first difference wins:

1. explicitly selected by the caller
2. relationship directness (safety class)
3. automatically eligible
4. not previously enriched
5. supported target type
6. relationship fan-out — fewer links first
7. distance from root
8. node key

No weighted score. There is no evidence for any weighting over "directness" and
"fan-out", and a made-up formula produces a number that looks principled, cannot
be explained to an analyst, and shifts unpredictably when a provider starts
returning more objects.

**Source-family count is deliberately not a factor.** It is recorded and displayed
because two independent families observing one link is genuinely more interesting
than one — but ranking on it is the first step towards "two providers agreed,
therefore malicious", which is a fusion judgement this layer must not make.

Nothing is ranked on AV detections, provider votes or any confidence figure.

---

## 6. Budgets are global

Task 13 spends a budget per observable. Five pivots at STANDARD would be five
fresh budgets — twenty remote calls from one submitted hash. So the pivot budget
is shared across the whole session:

| Root depth | Targets | Total remote runs | Pivot depth |
|---|---|---|---|
| QUICK | 0 | 0 | — |
| STANDARD | 2 | 3 | QUICK |
| DEEP | 5 | 8 | STANDARD |

TI Recon safety defaults, not provider quotas. QUICK is zero on purpose: it is the
triage depth, and triage that quietly fans out to third parties is not triage.

A caller may lower these and never raise them.

### Handed down, not merely watched

Each pivot's `EnrichmentPlanningRequest` receives
`max_remote_provider_runs = <what is left>`. So a DEEP session with eight runs,
where pivot A spent three, gives pivot B a *ceiling of five* — Task 13 is told, not
observed after the fact.

### Charged on real calls

Pivot cost is read from Task 13's own `budget.remote_runs_used`, which already
applies the rule: only a run that contacted a remote provider counts. A cache hit,
a coalesced request, an unconfigured credential, a cooldown, a quota pre-check and
every local provider cost nothing — because none of them disclosed anything.

Counting `called_provider` directly would be wrong here: a local provider *was*
called and disclosed nothing, and charging the disclosure budget for it would make
offline context artificially expensive.

### Depth downshift

A pivot runs one depth below the root. The root is what the analyst asked about; a
contacted domain is a lead, and running a lead at the root's depth spends as much
on a guess as on the question. `DEEP → STANDARD`, `STANDARD → QUICK`, never
`DEEP → DEEP`.

---

## 7. One hop, and only one

```
root (hop 0)     file
hop 1            contacted domain    <- may be enriched
hop 2            addresses, URLs     <- graphed, never enriched
```

`MAX_AUTOMATIC_PIVOT_HOP = 1`. Objects a pivot discovers enter the graph — discovery
is cheap and useful — and are never queried about. They appear in the candidate
list carrying `HOP_LIMIT`, because seeing a lead and being allowed to chase it are
different things, and an analyst asking "what else is in here?" should not be
answered with silence.

Without this, a file contacts forty domains, each resolves to ten addresses, each
address serves a hundred URLs: tens of thousands of third-party queries about
objects nobody chose to investigate.

### Cycles

Graph cycles are legitimate — A contacts B, B serves A. Traversal loops are not.
A target is marked enriched **before** its results are ingested, so a result naming
the target again, or naming the root, cannot queue it a second time. A canonical
target is enriched at most once per session; a repeat is reported as
`ALREADY_ENRICHED`.

The same domain named by three providers is one node, one candidate and one
enrichment — with all three assertions kept on its edges.

---

## 8. Reason codes

Selection — operational, never a claim about threat:

```
EXPLICIT_SELECTION   DIRECT_ARTIFACT_RELATION
DIRECT_BEHAVIOR_RELATION   ENRICHABLE_TARGET
```

Skips:

```
MODE_DISABLED        RECOMMEND_ONLY         RELATION_NOT_ELIGIBLE
ALREADY_ENRICHED     NON_GLOBAL_IP          SENSITIVE_URL
UNNORMALIZABLE_TARGET
UNLINKED_OBJECT      UNSUPPORTED_TARGET     HOP_LIMIT
TARGET_BUDGET        REMOTE_BUDGET          REMOTE_PIVOTS_DISABLED
GRAPH_LIMIT
```

Every one is operational. "We did not ask" is not "there was nothing to find".

Skipped candidates are returned alongside selected ones, because *why was this not
followed* is the more common analyst question and a list that omitted its
rejections would answer it with silence.

---

## 9. Task 14 never resolves anything

No DNS lookup. No HTTP request. No socket. No download. A pivot is a canonical
observable passed to Task 13, and Task 13's providers decide what passive lookups
they make. A test reads the AST of every correlation module to confirm none of
them imports `socket`, `httpx`, `requests`, `urllib.request`, `dns` or `asyncio`,
names a provider package, or touches the credential layer.

---

## 10. The flow

```
   observable
       |
   Task 13 adaptive enrichment
       |
   provider results ----> Task 14 correlation engine
                              |
                        investigation graph
                              |
                        pivot candidate ranking
                              |
             NONE / RECOMMEND / explicit ENRICH
                              |
                        Task 13 again, at reduced depth,
                        with the remaining shared budget
                              |
                        ingest at hop 2 (never enriched)
```

`CorrelatedEnrichmentResult` keeps each Task 13 run identifiable by the node it
was about and the hop it sat at, rather than flattening every provider outcome
from every pivot into one list. "Which of these findings is about the thing I
submitted?" has to stay answerable.

---

## 11. Explainability

Everything an analyst needs, without an LLM in the loop:

| Question | Where |
|---|---|
| Why does this node exist? | `GraphNode.occurrences` — provider, family, lineage, hop |
| Who reported it? | assertion `transport_provider` / `origin_provider` |
| How was it linked? | edge `relationship_type` + `raw_relationship_type` |
| Observed or derived? | assertion `basis` |
| Which families asserted it? | `edge.asserting_source_families` |
| When? | per-assertion `first_seen` / `last_seen` |
| Was it enriched? | `GraphNode.enriched`, `pivot_runs` |
| Why (not) a pivot? | `PivotCandidate.selection_reason` / `skip_reason` |

---

## 12. Metrics

Counts and enum members only — graph size, assertions deduplicated, identity
conflicts, candidates, pivots enriched, skips by reason, truncation. No field can
hold an observable, a node key, an investigation id or a user: this layer sees more
observables than any other, because it sees everything the providers returned, and
a metric labelled with the IOC would turn a metrics pipeline into a record of
everything every analyst has looked at.

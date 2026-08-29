# Investigation graph

Task 14. `src/ti_recon/correlation/`

Takes what Task 13 learned about one observable and turns the objects and
relationships providers returned into a single graph: which records refer to the
same underlying object, which relationships were claimed, who claimed each of
them, and how they came to know.

It answers *what have we learned*. It does not answer *is this malicious* — there
is no verdict, no confidence and no score anywhere in the package, and a test
walks the result's nested keys to keep it that way.

Controlled pivoting — deciding which of the discovered objects are worth asking
about — is [controlled-pivots.md](controlled-pivots.md).

---

## 1. Scope: one investigation, one user

The graph is in-memory, built per run, and thrown away with it. Two analysts
investigating the same domain produce the same canonical node keys and two
entirely separate graphs.

That is deliberate. A shared correlation store would make one analyst's pivots
visible in another's investigation, which leaks *who is looking at what* — a
different and more sensitive thing than the observables themselves. Provider
caching is Task 6's business and stays there, scoped by user as it already is.

There is also **no graph database**. At investigation scale the queries are
"neighbours of this node" and "walk one hop", which a dict answers instantly;
Neo4j would buy an operational dependency and a second query language for nothing.
Persistence, when it comes, can be PostgreSQL with none of these semantics
changing.

---

## 2. Node identity is exact

A node exists once per *observable identity*, derived from the Task 3 canonical
key — so correlation identity is the identity the rest of the system already uses.

| Observable | Key |
|---|---|
| IPv4 / IPv6 | `ipv4-addr:8.8.8.8`, canonical form |
| Domain | `domain-name:example.com`, canonical IDNA, case-folded |
| URL | `url:https://example.com/a`, the existing conservative canonicalization |
| File | `file:sha256:<digest>`, strongest available hash |
| Certificate, ASN, malware | `<type>:<canonical value>` |

Nothing else contributes. Not the provider, the investigation, the display value,
a tag, a label or a family — those describe an *observation*, not an object.

### What is never identity

Records are merged only when they are the same object:

```
same ASN            same /24              same hosting provider
same TLS issuer     same certificate CN   same page title
same favicon        same ssdeep           same TLSH
same imphash        same malware family   same YARA rule
same tag            same ATT&CK technique same URL host
```

Every one of these is a real analytic signal and none of them is identity. Merging
on resemblance makes every later statement about "this object" quietly untrue, in
a way nothing downstream can detect — and several of the signals above are things
an attacker chooses. Similarity clustering is worth building; it belongs on top of
exact relationships that can be trusted, not underneath them.

Two consequences worth stating:

- `https://example.com/a` and `https://example.com/b` are **two** URL nodes that
  both hang off one host node. Collapsing them is how a payload on a trusted site
  inherits the site's reputation.
- Two addresses in one /24 are two nodes. CIDR membership is context on a node,
  never node identity.

---

## 3. File identity, carefully

A file is the one observable whose identity arrives in pieces: one provider
answers with a SHA-256, another with an MD5, a third binds all three. Since the
canonical key names a file by its *strongest available* digest, the same sample
legitimately produces `file:sha256:AAA` from one provider and `file:md5:BBB` from
another, and something has to decide whether those are one sample.

`FileIdentityResolver` decides conservatively:

| Situation | Result | Basis |
|---|---|---|
| shared SHA-256 | merge | `SHA256` |
| shared SHA-1, nothing stronger disagrees | merge | `SHA1` |
| shared MD5, nothing stronger disagrees | merge | `LEGACY_MD5` |
| provider bound several digests to one sample | merge | `PROVIDER_MULTI_HASH_BINDING` |
| **shared weak hash, stronger hash disagrees** | **no merge** + issue | — |

The last row is the one that matters. Two files sharing an MD5 and differing in
SHA-256 are the textbook collision, manufacturable on a laptop; merging them would
fuse two samples into one node and attribute each one's behaviour to the other.

The basis is recorded rather than flattened into "hashes matched", because these
are not equally strong and a later layer may want to weigh that.

Aliases accumulate across providers and arrival order:

```
provider A:  SHA-256 = A, MD5 = B
provider B:  SHA-256 = A, SHA-1 = C
node:        sha256:A  sha1:C  md5:B
```

A held digest is never overwritten. A conflicting value stops the merge instead.

---

## 4. An edge is a claim, not a fact

```
GraphEdge                       one semantic relationship
  source_key
  relationship_type
  target_key
  assertions[]                  who claimed it, and how they knew
```

Two providers saying "this file contacted evil.example" is **one** edge with
**two** assertions. Splitting them into two edges invents a second relationship;
collapsing them into one assertion loses a genuine independent observation.

The edge key is `(source, type, target)` and carries **no provider** — that is what
makes two providers' claims meet.

### Assertion provenance

Each `RelationshipAssertion` keeps what Tasks 3-12 established:

- `transport_provider` — who handed it to TI Recon
- `origin_provider` — who produced it
- `source_family` — which ecosystem it belongs to
- `lineage_group_id` — which observation it came from
- `raw_relationship_type` — the provider's own field name
- `first_seen` / `last_seen` / `observed_at`
- `evidence_id` — the record behind it

A relayed finding keeps the origin of whoever produced it: a VirusTotal figure
relayed through URLhaus is transported by `urlhaus` and originated by
`virustotal`, and the graph never lets that read as URLhaus having observed
anything.

### Deduplication

One provider commonly renders the same relationship three ways — in its evidence,
in its related objects, and again in a summary. The assertion dedupe key is
`(basis, source_family, lineage_group_id, origin_provider, raw_relationship_type)`,
which collapses those into one while leaving two providers' independent claims
both standing. It also lets one provider assert two genuinely different links
between the same pair — `contacted_domains` and `embedded_domains` are different
claims.

### Source families are shown, never counted into a score

`asserting_source_families` is exposed because two independent families observing
one link is genuinely more interesting than one. It is **not** confidence:

```
ThreatFox + URLhaus  ->  ('abuse_ch',)                    one family
GTI + Hybrid Analysis ->  ('google_ti', 'hybrid_analysis') two families
```

Nothing in this package turns that count into a number, and the pivot ranking
deliberately does not order on it.

---

## 5. Canonical orientation

Providers describe the same fact from either end:

```
urlscan:  URL served this file
GTI:      this file came from that URL   (itw_urls)
```

Stored as written those are two unrelated-looking facts. Each relationship
definition names one canonical orientation, and an assertion arriving the other
way round is flipped onto the same edge:

```
url:https://evil.example/a.exe --downloads--> file:sha256:B
   assertions: urlscan (lists.hashes), gti (itw_urls)
```

Traversal is undirected — `incident_edges` and `neighbours` do not care which way
a provider phrased it. Only storage is single-directional, so the assertions meet.

Endpoints that do not fit a relationship's meaning (a domain "dropping" a file)
are refused with an `ENDPOINT_TYPE_MISMATCH` issue rather than stored as though
they made sense.

---

## 6. The canonical vocabulary

Only the relationships Tasks 7-12 actually emit are defined. Nine of the thirteen
`RelationshipType` members; the rest are left undefined, because a definition
nobody produces is a rule nobody has tested. `similar-to` and `duplicate-of` are
pointedly among the undefined: correlation merges on exact identity, so giving
similarity graph semantics would invite the fuzzy merging this task refuses.

| Canonical | Endpoints | Safety class | Pivot |
|---|---|---|---|
| `downloads` | url/host → file | direct artifact | eligible |
| `drops` | file → file | direct artifact | eligible |
| `contacts` | file/url → host/url | direct behavior | eligible |
| `redirects-to` | url → url | direct behavior | eligible |
| `resolves-to` | domain → address | infrastructure | recommend only |
| `hosts` | host → url | structural | recommend only |
| `uses-certificate` | host/file → certificate | infrastructure | recommend only |
| `belongs-to-asn` | host → AS | infrastructure | never |
| `associated-with-malware` | artifact → malware | generic | never |
| `related-to` | any → any | generic | never |

### Provider mappings

Raw-to-canonical mapping stays with the provider that owns the raw name; the
registry names no provider, and a test reads its AST to prove it.

| Provider | Raw field | Canonical |
|---|---|---|
| GTI | `contacted_domains`, `contacted_ips`, `contacted_urls`, `embedded_domains`, `communicating_files` | `contacts` |
| GTI | `dropped_files` | `drops` |
| GTI | `itw_urls`, `downloaded_files` | `downloads` |
| GTI | `resolutions` | `resolves-to` |
| GTI | `redirecting_urls` | `redirects-to` |
| GTI | `malware_families` | `associated-with-malware` |
| GTI | `associations`, `related_threat_actors`, `related_reports`, `campaigns` | `related-to` |
| urlscan | `data.requests.redirectResponse` | `redirects-to` |
| urlscan | `lists.domains`, `lists.ips` | `contacts` |
| urlscan | `lists.hashes` | `downloads` |
| urlscan | `lists.asns` | `belongs-to-asn` |
| GreyNoise | `metadata.rdns` | `resolves-to` |
| GreyNoise | `metadata.asn` | `belongs-to-asn` |
| Censys | `dns.names` | `resolves-to` |
| Censys | `services.tls.certificate` | `uses-certificate` |
| Censys | `autonomous_system` | `belongs-to-asn` |
| ThreatFox | `ioc`, `malware_samples` | `contacts` |
| ThreatFox | `malware_printable` | `associated-with-malware` |
| URLhaus | `urls`, `host` | `hosts` |
| URLhaus | `payloads` | `downloads` |
| MalwareBazaar | `code_sign` | `uses-certificate` |
| Hybrid Analysis | `network_observations` | `contacts` |
| Hybrid Analysis | `extracted_files` | `drops` |
| MISP Warning Lists | — | none; a match explains a node rather than linking two |

Building this table found a real mis-mapping: urlscan wrote `lists.ips` as
`page --resolves-to--> ip`. A page does not resolve, and the error put a live
connection in the same bucket as passive DNS, whose pivot policy is deliberately
much more cautious. It is now `contacts`.

---

## 7. Derived is not observed

`RelationBasis` records how a relationship came to be known:

| Basis | Meaning |
|---|---|
| `PROVIDER_OBSERVED` | the provider watched it happen |
| `PROVIDER_REPORTED` | the provider holds a record of it |
| `ENGINE_DERIVED` | TI Recon derived it from the observable itself |

A provider can say it watched something in two ways, and both are read:

- `EvidenceClass.DIRECT_OBSERVATION` on the evidence behind the relationship — a
  live page load, for instance;
- `Relationship.directly_observed` on the link itself.

The second exists because the two properties are **orthogonal**. A sandbox's
contacted domain is `EvidenceClass.CONTEXT` with `CONTEXT_ONLY` effect, since it
accuses nobody — a detonating sample also reaches CRLs, CDNs and time servers —
and it is simultaneously something the sandbox *watched happen*. Reading only the
class made every sandbox observation arrive as though it were a database lookup.

Either signal earns `PROVIDER_OBSERVED`; neither leaves `PROVIDER_REPORTED`. Both
are things a provider must assert, so silence is never read as observation and a
2019 passive-DNS row can never be presented as an eyewitness account.

The flag is set in the provider that knows — Hybrid Analysis marks its
`network_observations` and `extracted_files` links, and only for a run whose state
is complete, because an errored or queued report has no behaviour to have watched.
The correlation engine reads the field generically and names no provider; a test
asserts both halves.

Marking a link observed changes **nothing** else: not the evidence class, not the
effect, not the edge's direction, not its pivot safety class, and not the ranking —
observation basis is provenance, and a relationship does not become more followable
because somebody watched it.

### The one structural relationship

For a URL node, TI Recon derives `host --hosts--> url` from the authority the URL
already carries. The host is **parsed**, not searched for: a path that looks like a
hostname is not the authority.

It is `ENGINE_DERIVED`, names no provider and no source family — validated, not
merely documented — and lands on the same canonical edge a provider would assert.
So when URLhaus asserts the same host relationship, there is one edge with two
assertions and **one** source family: TI Recon's own parsing contributes nothing to
the count.

No resolution happens. No DNS relationship is created.

---

## 8. Time is preserved, never flattened

Times live on assertions, not on edges:

```
bad.example --resolves-to--> 1.2.3.4
   assertion: gti     first_seen 2019-03-04
   assertion: censys  last_seen  2026-01-09
```

Two observations, not a seven-year association. `earliest_observed` and
`latest_observed` exist on the edge for **display only**, and the code that
computes them says so: a bounding box around separate observations is not a claim
that the relationship held throughout.

An undated claim stays undated — no clock is consulted. And nothing here decides
whether a relationship is current, stale or expired: freshness reasoning needs
thresholds nobody has evidence for, and belongs in a later layer.

---

## 9. No inference

The engine correlates explicit relationships and one deterministic structural
relationship. It does not infer.

```
A --contacts--> B,  B --resolves-to--> C     never yields  A -> C
file1 --contacts--> IP,  file2 --contacts--> IP   never yields file1 -> file2
domain --resolves-to--> IP,  IP --uses-certificate--> cert
                                              never yields domain -> cert
```

The second is the most tempting and produces the most false links: shared
infrastructure is shared by everybody. If TI Recon ever infers, it will do so in a
layer that labels its output as inferred — the way OpenCTI distinguishes inferred
relationships — so an analyst can tell what somebody observed from what a rule
concluded.

Related to this: **no edge is created from a label.** A malware family, tag,
threat category, AV label, YARA rule, country, ASN owner or warninglist name does
not become a relationship. The one exception is where a provider already emits a
family association as a `Relationship` — GTI and ThreatFox do — and those edges are
`NEVER` pivotable, because a family is a name rather than an artifact.

---

## 10. Correlation issues

Data-quality problems, recorded rather than swallowed:

| Issue | Meaning |
|---|---|
| `FILE_HASH_CONFLICT` | weak hash matched, stronger one disagreed |
| `INVALID_RELATED_OBJECT` | an object could not be turned into a node |
| `DANGLING_RELATIONSHIP` | a relationship referenced an absent object |
| `UNKNOWN_RELATIONSHIP` | no canonical definition for this type |
| `ENDPOINT_TYPE_MISMATCH` | the endpoints do not fit the relationship |
| `GRAPH_LIMIT_REACHED` | a ceiling stopped the graph growing |

These are deliberately **not** `EvidenceConflict`, which relates two pieces of
intelligence that disagree about the world. An MD5 collision or a malformed
endpoint pair is a problem with the shape of the data, and filing it as a
disagreement between sources would put plumbing in front of an analyst as though
it were intelligence.

---

## 11. Ingestion

```
CorrelationEngine.ingest(envelope, hop=..., anchor_key=...)
  1. place the objects the provider returned
  2. resolve exact identity, merging files by digest
  3. validate each relationship against the vocabulary
  4. flip a backwards relationship onto its canonical orientation
  5. fold its provenance onto the semantic edge as an assertion
  6. mark objects that arrived with no relationship as unlinked
  7. derive the URL-host relationships
  8. record what the ceilings refused
```

The engine reads only what providers stated explicitly — the objects and
relationships on the envelope. Nothing parses evidence prose looking for
indicators: a regex over a description would invent relationships nobody asserted
and put a real provider's name on them, and the failure would be silent. Where a
provider knows something the graph needs, the fix is a small change in that
provider's normalizer.

`anchor_key` is the node the lookup was *about*. Several providers relate findings
to the observable without returning it among their objects — the subject is the
request, not a discovery — so without it every one of those relationships would
look like it pointed at something absent.

### Unlinked objects

An object a provider returned with no usable relationship is graphed and marked.
It is a real finding and throwing it away would lose it. It is never automatically
pivoted, and no `related-to` is invented to make the graph connected: a fabricated
edge would then look like the justification for querying third parties about it.

### Order independence

Feeding GTI, Hybrid Analysis and URLhaus in any order produces the same nodes,
edges and assertions. Identity comes from canonical keys, edge keys carry no
provider, assertion dedupe is by value, and iteration is sorted. The one thing that
depends on order is the hop at which a node was first *seen*, and even that keeps
the minimum.

---

## 12. Limits

| Ceiling | Default |
|---|---|
| `max_nodes` | 1000 |
| `max_edges` | 2000 |
| `max_assertions_per_edge` | 50 |
| `max_assertions` | 5000 |
| `max_pivot_candidates` | 200 |

Provider normalizers are bounded already; this is the final envelope, because
"bounded per provider" times "several providers" times "pivots" is not bounded.
None of these numbers is analytical — hitting one says nothing about an
investigation except that it was large.

Truncation is counted, not merely flagged: an analyst reading a graph that stopped
at a thousand nodes needs to know whether it dropped three or three thousand. One
issue is filed per ceiling rather than one per dropped item.

---

## 13. What this is not

- No verdict, risk score, confidence or false-positive reasoning. A warninglist
  match explains a node; it never deletes an edge. `malware --contacts--> 8.8.8.8`
  survives MISP saying 8.8.8.8 is a public resolver, because the observation
  happened and the context explains it.
- No threat-actor attribution, malware-family reconciliation or campaign
  clustering.
- No similarity or fuzzy correlation — ssdeep, TLSH, imphash, CIDR, ASN.
- No transitive or rule-based inference.
- No global cross-user graph, and no graph database.
- No freshness reasoning.

## What Task 15 reads from this graph

Task 15 qualifies the graph without changing it. Two things it takes, and one it
deliberately does not.

**Per-assertion times.** `RelationshipAssertion.first_seen`, `last_seen` and
`observed_at` become `RELATIONSHIP_FIRST_OBSERVED` / `RELATIONSHIP_LAST_OBSERVED`
facts, one set per assertion, each keeping its own asserter and `RelationBasis`.
An edge carrying a 2025 sighting and a 2026 sighting therefore qualifies as **two
observations**, never a one-year continuous association.

**Not the aggregate bounds.** `GraphEdge.earliest_observed` and
`latest_observed` are documented here as display-only bounding boxes, and Task 15
does not qualify them: turning a bounding box into a fact is exactly the
inference this layer refuses to make.

`RelationBasis` travels onto every relationship fact as provenance.
`PROVIDER_OBSERVED` says a provider watched the link happen — it is never mapped
toward a verdict about either endpoint.

The one place Task 15 reads *edges* is a single narrow rule: an incident
`contacts` edge whose target carries public-resolver context gets a
`PUBLIC_SERVICE_MAY_EXPLAIN_CONTACT` cue. One edge, no traversal, and the graph
is left untouched — a test asserts the edge count and the edge itself are
unchanged afterwards. See
[docs/reasoning/context-qualification.md](../reasoning/context-qualification.md).

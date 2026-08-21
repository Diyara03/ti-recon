# TI Recon — Product Scope and Investigation Workflow Foundation

> Task 1. This document defines *what TI Recon investigates*, the vocabularies an
> investigation uses, and what is deliberately out of scope. Vocabularies listed
> here exist as typed enums in `src/ti_recon/enums.py`; the engine that *uses*
> them (planner, fusion, verdict scoring) is a later task.

## 1. Problem

An analyst receives an artifact of unknown reputation — an IP from a firewall
log, a domain from a phishing mail, a URL from a ticket, a hash from an EDR
alert. Answering "is this malicious, and why should I believe you?" today means
opening five vendor portals, reading five different schemas, and mentally
de-duplicating data that several of those vendors bought from each other.

TI Recon does that enrichment once, in a normalized and provenance-tracked form,
and shows the reasoning rather than a single opaque score.

## 2. Supported inputs (V1)

| Input | Modelled as | Canonical key example |
|-------|-------------|-----------------------|
| IPv4 address | `ipv4-addr` | `ipv4-addr:198.51.100.7` |
| IPv6 address | `ipv6-addr` | `ipv6-addr:2001:db8::1` |
| Domain name | `domain-name` | `domain-name:evil.example` |
| URL | `url` | `url:http://evil.example/a` |
| MD5 hash | `file` (hash property) | `file:md5:<32 hex>` |
| SHA1 hash | `file` (hash property) | `file:sha1:<40 hex>` |
| SHA256 hash | `file` (hash property) | `file:sha256:<64 hex>` |

Submitted artifacts are called **Observables** internally — concrete observed
values, in the STIX Cyber-observable sense — rather than STIX *Indicators*
(which carry detection logic and a confidence assertion we do not have at input
time). Analyst-facing text and documentation may still use the familiar word
*IOC*.

Analyst-friendly input handling that is in scope:

- defanged forms: `evil[.]example`, `hxxp://…`, `hxxps://…`
- mixed case, surrounding whitespace, trailing dot on domains
- internationalized domain names (normalized to IDNA/A-label)

Explicitly **not** in scope for input handling: DNS resolution, WHOIS lookup, or
any other network activity during normalization. Normalization is syntactic only.

## 3. Out of scope

Out of scope for V1, and out of scope for the current Tasks 1-5 foundation:

```
file uploads                      automatic URL submission
automatic sandboxing              automatic file submission
EDR / firewall blocking           direct browsing of IOC URLs
SIEM response actions             sample downloads
threat actor attribution          Telegram monitoring
                                  dark-web monitoring
```

Two of these are hard security boundaries rather than backlog items:

- **Direct browsing of IOC URLs is never in scope.** A suspicious URL is
  submitted to a provider API (e.g. urlscan) that is built to visit it. TI Recon
  itself must never fetch analyst-supplied URLs; the HTTP transport is pinned to
  configured provider hosts to make this structurally impossible.
- **Active actions require explicit user approval** and live on a separate code
  path from passive enrichment. None are implemented.

## 4. Investigation workflow (target)

```
1. Input          analyst submits raw text
2. Normalize      -> Observable (IntelObject), canonical value + canonical key
3. Plan           which capabilities does this object type need?      (future)
4. Resolve        which configured providers cover those capabilities?
5. Query          passive lookups, per provider, async               (future)
6. Normalize      provider payload -> Evidence + IntelObject + Relationship
7. Lineage        de-duplicate relayed intelligence by origin_provider (future)
8. Fuse           weigh evidence: freshness, independence,
                  specificity, false-positive context                (future)
9. Assess         verdict + risk score + confidence + coverage       (future)
10. Explain       show contributions, conflicts and coverage gaps     (future)
```

Steps 1-2 and the data structures for 4-9 exist today. Steps 3, 5, 7, 8, 9 and
10 are later tasks.

Coverage is a first-class output: an investigation reports which capabilities it
*could not* satisfy (`CoverageItem`), so an inconclusive result is
distinguishable from a clean one.

## 5. Verdict vocabulary (future output)

```
MALICIOUS         evidence supports a malicious determination
SUSPICIOUS        concerning evidence, insufficient for MALICIOUS
INCONCLUSIVE      insufficient or conflicting evidence
LIKELY_BENIGN     evidence supports benign, stated as likelihood not proof
```

There is deliberately no `BENIGN`: passive external intelligence cannot prove
absence of malice.

## 6. Investigation depth

```
QUICK       minimal capability set, fastest answer, lowest quota cost
STANDARD    default; the capabilities relevant to the object type
DEEP        adds historical / pivot / relationship capabilities
```

Depth influences which capabilities are requested and how much pagination is
allowed. It never changes the meaning of evidence.

## 7. Activity mode

```
PASSIVE     default. Read already-existing provider intelligence only.
ACTIVE      operations that cause new interaction with the target.
```

Passive examples: existing VirusTotal report, existing urlscan result, GreyNoise
lookup, Censys lookup, ThreatFox lookup.

Active examples (not implemented): submit URL, submit file, rescan, sandbox run.

`PASSIVE` is the default everywhere. `ACTIVE` will require explicit per-request
user approval and a provider that advertises `supports_active`.

## 8. Non-functional requirements

- **Provider independence** — no investigation may depend on any one vendor.
- **Explainability** — every assessment traces to evidence, and every piece of
  evidence traces to a provider run and a raw response reference.
- **Multi-tenant safety** — each user's provider credentials are isolated.
- **Auditability** — `engine_version`, `policy_version`, `adapter_version` and
  `api_version` are recorded so a past verdict can be explained later.

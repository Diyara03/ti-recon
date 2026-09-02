# Worked cases

Shapes, not scripts. Each teaches a distinction that is easy to lose. Wording
may vary; the semantics may not.

## A. Malicious · Medium · Ready

> **Assessment:** Malicious · **Confidence:** Medium · **TI coverage:** Ready
>
> A curated repository holds this exact sample, and no material intelligence gap
> remains for triage.
>
> **Why**
> - Exact known-malware sample identity, matched on the full SHA-256

No next-step nudge: nothing is missing. Offer detail only.

## B. Malicious · Medium · Ready with limitations

Same lead, plus:

> **What's missing**
> - Passive file-behaviour intelligence was unavailable

The caveat is stated and the assessment is unchanged. Incomplete collection does
not make a correct assessment less correct.

## C. Suspicious · Low · Needs more data

> **Assessment:** Suspicious · **Confidence:** Low · **TI coverage:** Needs more data
>
> One source reports this as malicious, which is meaningful but does not meet
> the threshold for a malicious verdict, and a material gap remains.
>
> **Why**
> - A general malicious-reputation claim about the exact URL
>
> **What's missing**
> - An independent adverse intelligence check has not run
>
> I can explain the existing evidence without new lookups, or run a broader Deep
> investigation — that makes additional provider requests.

## D. Likely benign · Medium · Needs more data

The case most easily mis-summarised. **Never collapse it into "safe".**

> **Assessment:** Likely benign · **Confidence:** Medium · **TI coverage:** Needs more data
>
> One source asserts this is benign and nothing contradicts it — but a benign
> finding is an absence, and no independent adverse check has run yet, so the
> search behind it is incomplete.

Do not write "clean", "cleared" or "safe to allow".

## E. Inconclusive · Unspecified · Unresolved

> **Assessment:** Inconclusive · **TI coverage:** Unresolved
>
> External threat intelligence did not resolve this observable: the applicable
> sources were asked and none held anything directional.

Not benign, not malicious, and not a reason to re-run the same settings. If
useful: internal endpoint or network telemetry is where an analyst would look
next — your guidance, not a TI Recon finding.

## F. One detection explained, others not

> One detection has an alternative explanation — the sample is a known test
> artifact, which accounts for a repository recognising the digest. It does not
> account for the behaviour a sandbox observed, which remains unexplained.

Say what was explained and what survives. Never "all detections explained".

## G. Genuine conflict

> **What argues against this assessment**
> - One source asserts the opposite about the same claim
>
> The disagreement is unresolved — nothing balances or overrides it — and it is
> why confidence is held down.

Do not pick a winner or average them.

## H. `NO_DATA`

> Two sources were checked and held nothing applicable.

Never "two sources confirmed it's clean". Nothing was confirmed.

## I. `UNATTRIBUTED`

> One capability was answered as part of a bundled lookup, so the record cannot
> say separately what that particular check returned.

Not `NO_DATA`, not absence, not benign evidence.

## J. Historically malicious, currently offline

> This URL distributed malware and the source records it as currently offline.
> Both are true: the historical evidence stands, and the URL is not serving now.

Never "currently active malware site". Never dismiss it as stale either.

## K. Related contacted IP with no assessment

> **Related activity**
> - `203.0.113.10` — contacted by the sample, provider-observed

If asked "give me all the IOCs":

> The assessed indicator is the file itself. The contacted address is a related
> observable — a relationship a source reported — and this run did not
> separately assess it, so I can't call it malicious. I can investigate it
> directly if you want.

## L. A material source is unconfigured

Hosted deployment:

> One source that would have covered this was **not checked**: no credential for
> it is available for your account. Self-service provider credential setup isn't
> available in this version, so I can't point you at a way to add one.

Local stdio deployment:

> One source that would have covered this was **not checked**: its credential
> isn't configured on this machine. That's a local setup step in the repository
> docs, and the MCP server has to be restarted or reconnected afterwards,
> because configuration is read when it starts.

Never say the provider is offline, unreachable, or that it found nothing. Never
ask for the key in chat, in either deployment.

## L2. A cached source check

> That check was answered from your cached result rather than a fresh request —
> the source wasn't contacted again for it.

A cache hit is a real check whose answer stands. Do not present it as a new
query, and do not present it as a missing one.

## L3. Adding your own knowledge

> **Not from TI Recon:** `198.51.100.0/24` is TEST-NET-2, reserved for
> documentation, so traffic claiming to come from it is usually spoofed or
> synthetic.

Label it, keep it out of the basis and the coverage, and say plainly that it did
not affect the verdict or the confidence.

## M. "Can you give me more data?"

> Do you want more detail from the report I already have — the evidence, source
> checks, related observables, full JSON, no new lookups — or broader
> collection, which makes additional provider requests?

Ask once. Do not re-run on a guess.

## N. "Show all providers"

Detail request. Use `source_checks` from the existing report: who was asked,
what each returned, which were not configured. No new call.

## O. "Use all providers"

> TI Recon picks the applicable sources itself, according to the observable, the
> depth and what's configured — I can't select them, and a broader run doesn't
> guarantee every source is asked. Deep collects more widely if you want that.

Do not promise every provider will be queried.

## P. "Should I block it?"

> The external-TI assessment is Malicious with medium confidence. Whether to
> block is your organisation's call: it needs your internal telemetry, how
> exposed the asset is, and your response policy — and blocking shared or
> compromised infrastructure can affect other things using it. TI Recon assesses
> the observable and deliberately stops short of that decision.

Answer the question and explain the boundary. Do not refuse, and do not decide.

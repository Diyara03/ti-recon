# The remote identity boundary (Task 22)

TI Recon will eventually serve MCP over authenticated HTTPS as well as over local
stdio. This page describes the part that exists now: **who a request belongs to,
and what stops one analyst's work reaching another's**.

> **There is no HTTP entry point yet.** No Streamable HTTP endpoint, no
> `AuthSettings` wiring, no health route, no remote console command. Those are
> built on this boundary rather than beside it, because an isolation model that
> arrives after the transport is a model nobody can prove. Today the only running
> server is `ti-recon-mcp` over stdio, documented in [mcp.md](mcp.md).

## The role TI Recon plays

An OAuth **resource server**, and nothing more. It issues no token, stores no
password, runs no login page and registers no client. An organization's own
authorization server authenticates the analyst and issues access tokens; TI Recon
decides whether a token that arrived was issued *for TI Recon*, *by the expected
issuer*, and *for somebody*.

Nothing in the code names an identity provider. A deployment supplies its own
verifier, so a signed-JWT validator and an RFC 7662 introspection client are both
first-class and neither is the product requirement.

## Two verifiers, and why

```
deployment's own TokenVerifier   ← proves the token
        ↓
StrictTokenVerifier              ← proves it is ours
        ↓
MCP bearer middleware            ← 401 / 403, and the ContextVar
```

The **delegate** owns everything format-specific: signature or introspection,
`nbf`, `active`, RFC 9068's `typ`, revocation. Only it knows what the token is.

The **strict wrapper** never looks at the bearer string. It is not a JWT parser,
decodes nothing, and accepts a completely opaque token if the delegate verified
one. What it enforces holds for every format:

| Invariant | Why it cannot be left to the delegate |
| --- | --- |
| `subject` present and non-empty | There is no principal to serve without one. |
| `iss` exactly the configured issuer | Exact string comparison, as RFC 8414/9207 define issuer identity. `https://x` and `https://x/` are two issuers. |
| the token names *this* MCP resource | The SDK never checks it. |

That last row is the important one. The installed SDK's `BearerAuthBackend`
checks the header shape, calls the verifier and checks expiry — and reads
`AccessToken.resource` or an `aud` claim nowhere at all. A resource server that
skipped the audience check would accept any token its identity provider ever
issued for any API: the confused-deputy failure the MCP specification names
directly.

Audience may arrive as `AccessToken.resource` (RFC 8707), as an `aud` claim (a
string or a list), or both. Either establishing the expected resource is enough.
**Where both are present and disagree the token is refused**, rather than resolved
in whichever direction is convenient — a verifier whose two audience views
contradict each other has said it does not know what the token is for.

Time is deliberately absent from the wrapper. The delegate owns format-specific
freshness and the SDK independently refuses an expired token; a third clock policy
would be a second arbitrary answer to a question already answered twice.

**There is no permissive verifier in `src`.** Nothing decodes a token without
proof, trusts a claim it was handed, or accepts a bearer string on the strength of
its issuer alone, and no development-mode escape hatch is reachable from a
production composition. Fakes are test fixtures.

## The pseudonymous tenant identifier

Identity below the MCP layer is one string:

```
tenant-v1:<64 hex characters>
  = HMAC-SHA-256(
        tenant_key,
        framed("ti-recon/remote-tenant/v1") ‖ framed(issuer) ‖ framed(subject)
    )
```

where `framed(x)` prefixes an eight-byte big-endian length.

**Issuer *and* subject.** `sub` is unique only per issuer, and two organizations
can both have an analyst called `alice`; deriving from the subject alone would
hand one of them the other's credentials. The OAuth `client_id` is not used at
all — it identifies Claude Code, not the person typing into it, and using it
would collapse every analyst in an organization into one tenant.

**Keyed, not a plain digest.** A subject is routinely an email address, a
username or an employee number. `sha256(issuer + subject)` of a value like that is
pseudonymous only against casual inspection: anyone who obtains a scope identity,
a metrics export or a credential dump can enumerate a corporate directory offline
and recover every analyst. HMAC under a deployment secret removes the dictionary
attack — without the key there is nothing to enumerate against.

**Framed and domain-separated.** `iss="https://a" sub="bc"` and
`iss="https://ab" sub="c"` are different principals, and plain concatenation would
make them one tenant.

**Nothing is normalized** — no case folding, no trimming, no Unicode rewriting, no
URL normalization. Issuer and subject semantics belong to the identity provider,
and "tidying" them would invent an equivalence the IdP never stated.

Call it *pseudonymous*. Not anonymous, not irreversible, not collision-free: it
identifies a person, and the deployment can recompute it. What it buys is that the
raw subject never reaches a cache key, a cooldown key, a metric or a credential
record.

### The tenant key is durable deployment configuration

It is a TI Recon secret — not a provider API key, not an OAuth access token, not
the OAuth client secret — and its only use is this derivation. It has no default,
and an empty one is refused at construction.

**It must stay stable for the life of an environment.** Change it and every
analyst becomes a new tenant: Task 23 will key durable credential ownership on
these identifiers, so a rotated key would orphan every stored credential. Rotation
and migration are deliberately not implemented. It is never logged, serialized,
or rendered — not its value, and not its length, prefix or digest.

## The token stops at the MCP boundary

An MCP access token authorizes *the analyst to call TI Recon*. A provider
credential authenticates *TI Recon to a provider*. They come from different trust
domains, and the MCP token must never be forwarded to GTI, VirusTotal, urlscan,
GreyNoise, Censys, abuse.ch, Hybrid Analysis or anything else.

This is structural rather than procedural. `RemotePrincipal` carries one field —
`tenant_id` — and the token, the raw issuer, the raw subject, the `client_id` and
the claims all stop where it was built. Below `mcp_server/`, nothing imports the
MCP SDK, names an authentication symbol, or imports any ASGI machinery that could
read an inbound header; static tests read the AST of every module in
`application/`, `investigation/`, `planning/`, `correlation/`, `execution/`,
`credentials/`, `providers/`, `reasoning/`, `reporting/` and `cli/` to prove it. A
passthrough would have to add an import first.

A runtime regression drives the real seam as well, with a planted token string,
and asserts it reaches no provider request, no report, no result, no log and no
exception.

## One application, many analysts

Both deployment profiles share one `InvestigationApplication`, one
`ProviderExecutor` and one set of Task 6 stores. **Identity is request-scoped**:
every tool invocation builds a fresh `ExecutionContext`, and the principal comes
from a `PrincipalSource` — a fixed reserved name for stdio, the validated access
token of the request being served for remote.

That is safe because the isolation lives in the key rather than in the object.
Task 6 derives its cache, cooldown, quota, concurrency and single-flight keys from
`authenticated_user_id`, and the credential layer refuses a lookup that does not
name whose secret is wanted. Two analysts sharing one executor share nothing.

An application *per* user would throw away the cache for no gain. A server-wide
`current_user` field would be a race. Neither exists.

The request id is fresh per call too. It identifies one execution to the execution
layer, is never derived from the observable, and is never accepted from a caller —
and it appears in neither the internal result nor the public report, which is what
makes changing it safe for Task 20's contract.

## Remote provider credentials are never read from the environment

`build_stdio_runtime` reads this machine's environment once at startup, for the
one analyst who owns the process. `build_remote_runtime` **does not**, and that is
the point of the profile rather than an oversight.

A server's environment is global to the server. Loading it remotely would hand
every authenticated analyst the same keys, spend one quota on everybody's behalf,
share one abuse.ch fair-use block between strangers, and use a provider account
under terms nobody agreed to. Each analyst's provider credentials belong to that
analyst. An organization-wide shared credential would be a deliberate deployment
mode with its own decision — never a default nobody chose.

A regression sets every documented credential variable to an obvious fake and
asserts remote composition creates no connection for anybody.

### Where remote credentials will come from

The existing credential layer already supports everything the domain needs:
per-user connections keyed by `(user_id, credential_group)`, one connection per
group, create / rotate / disable / delete / list, and a `SecretStore` seam. What is
missing is a durable encrypted backing store and an authenticated path to fill it.
Both are **Task 23**, and neither is an MCP tool: a `set_api_key` tool would put a
provider secret through a model prompt, into tool arguments and into a transcript.

Until then a remote deployment seeds connections through `CredentialManager`
directly. A fully authenticated analyst with no provider credentials still gets a
valid report — local sources answer, remote ones report `NOT_CONFIGURED`, and
Task 18 records what that cost the coverage.

## Authenticated is not provider-configured

Two independent states, and collapsing them would be a real product error:

| Question | Answer |
| --- | --- |
| Can this person call TI Recon? | OAuth. Failure is `401`/`403`. |
| Does this person have provider credentials? | Coverage. Failure is `NOT_CONFIGURED`. |

A valid token with no provider keys is a successful tool call returning a real
report. Missing provider keys never become an authorization failure, and a
`MALICIOUS`, `INCONCLUSIVE` or `UNRESOLVED` outcome is a successful tool call.

## `provider_status` answers for the caller

`configured` means *you* have the required credential stored — not that some user
has it, not that the process environment has it, and not that server startup saw
it. It is read from the shared connection repository, scoped by user and credential
group, which is one authoritative path rather than a startup snapshot that would
answer a different question on a multi-tenant deployment.

Everything else is a catalogue fact and identical for everyone: provider id, source
family, locality, capabilities, object types, credential group, dataset version.

`configured` is a boolean. Never a value, a prefix, a length, a digest, a
connection id or a secret reference. The call contacts nothing — no provider, no
DNS, no socket, and no call back to an authorization server beyond the
authentication the current request already completed.

Stdio behaviour is functionally unchanged: the environment load still happens once
at startup, so **changing a credential still requires restarting the server**.

## Errors reveal nothing

A refused token is refused. The verifier distinguishes internally between a
delegate rejection, a wrong issuer, a wrong audience, contradictory audience
representations and a missing subject — logged as a bare reason code, so an
operator can diagnose a misconfiguration — but externally all of them are one
answer. "Your token's audience was X" tells an attacker what X should have been.

Task 21's unexpected-exception sanitisation is unchanged: the type is logged, the
message is not, and `CancelledError` propagates untouched.

## Still to come

**Task 22, next phase** — the Streamable HTTP endpoint itself: `AuthSettings` and
RFC 9728 protected-resource metadata, explicit `TransportSecuritySettings` with the
deployment's real hostname, `stateless_http`, a deployment-specific tool surface
without `investigate_file`, a health route, a scope, and the remote entry point.

**Task 23** — secure provider credential management: durable encrypted per-user
storage, an authenticated out-of-band provisioning path, rotation, revocation and
audit.

**Task 24** — production packaging and operations: container, ingress, worker
policy, rate limiting, timeouts, metrics and tracing.

# The authenticated remote MCP surface (Task 22)

TI Recon serves MCP over local stdio, and — through
`build_remote_http_app` — over OAuth-protected Streamable HTTP as well. This page
describes both halves of the remote work: **who a request belongs to**, and **the
HTTP surface that identity protects**.

> **Nothing is deployed, and no identity provider has been contacted.** The
> `ti-recon-mcp-http` process exists and starts; pointing it at a real
> authorization server and completing a Claude Code OAuth login is the next
> phase. The local `ti-recon-mcp` stdio server is unchanged — see
> [mcp.md](mcp.md).

```
HTTPS ingress
  -> transport preflight   Host, Origin, POST content type
  -> public routing        /health answered here, never below
  -> OAuth verification    the delegate, then the strict wrapper
  -> scope enforcement     ti-recon:investigate
  -> RemotePrincipal -> request-scoped ExecutionContext
  -> Task 20 -> 19 -> 13 -> 6 -> providers
```

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

## The HTTP surface

### Running one

```bash
export TI_RECON_MCP_RESOURCE_URL=https://mcp.example.com/mcp
export TI_RECON_AUTH_ISSUER_URL=https://idp.example.com/
export TI_RECON_AUTH_JWKS_URL=https://idp.example.com/.well-known/jwks.json
export TI_RECON_TENANT_DERIVATION_KEY_B64=...      # see below
export TI_RECON_MCP_ALLOWED_HOSTS=mcp.example.com
ti-recon-mcp-http
```

Optional: `TI_RECON_MCP_ALLOWED_ORIGINS` (empty by default),
`TI_RECON_AUTH_ALGORITHMS` (`RS256`), `TI_RECON_AUTH_TOKEN_PROFILE`
(`generic_jwt` or `rfc9068`), `TI_RECON_MCP_BIND_HOST` (`127.0.0.1`),
`TI_RECON_MCP_BIND_PORT` (`8000`), `TI_RECON_LOG_LEVEL`.

Nothing generic is read — no bare `API_KEY`, `TOKEN` or `SECRET` — and **no
provider credential is read at all**. Startup fails before the socket opens if
anything is missing or unsafe: no tenant key, a short one, an `http://` resource,
a path that is not `/mcp`, a wildcard host, a symmetric algorithm. A remote
server that started in a degraded, unauthenticated mode would be worse than one
that did not start.

**The public resource and the internal bind are different things.** A container
binds `0.0.0.0:8000` behind an ingress terminating TLS at
`https://mcp.example.com/mcp`; the canonical OAuth resource is always the
configured public HTTPS URL, never the socket.

**The tenant derivation key is base64url-encoded random bytes**, at least 32 of
them decoded, generated once by something cryptographically secure:

```bash
python -c "import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

The `_B64` in the variable name is the contract. HMAC-SHA-256 takes a key, not a
passphrase — a memorable 32-character string would make every tenant identifier
in the deployment only as strong as somebody's choice of words, and a resource
server has no business stretching a password into key material. Decoding is
strict: an invalid character, a short result or the standard (non-URL) base64
alphabet all refuse to start, and padding is optional.

**It must come from the deployment's secret store and stay stable.** It is never
generated at startup, and changing it changes every pseudonymous tenant
identifier — after Task 23 that would disconnect analysts from their stored
provider credentials. Back it up with the rest of the deployment's secrets and do
not rotate it casually; a safe migration is Task 23's to design if it is ever
needed. There is exactly one key, and no support for a second.

### Verifying a token

`JwtJwksTokenVerifier` is the production delegate. An authorization server signs
an access token with its private key and publishes the public half at a JWKS
endpoint; the verifier fetches that key once, caches it, and thereafter validates
locally.

| Checked | How |
| --- | --- |
| signature | asymmetric only — RS/PS/ES. **HS256 cannot be configured**, so an RSA public key can never be abused as an HMAC secret |
| `alg` | from the configured allowlist, never from the token header. `alg: none` is refused before a key is looked up |
| key | by `kid` from the configured JWKS URL. **`jku`, `x5u`, `jwk` and `x5c` are never read**, so a token can neither bring its own key nor point retrieval at a host it controls |
| key strength | `enforce_minimum_key_length`, so an RSA modulus under 2048 bits is an error rather than PyJWT's default warning |
| key purpose | a JWK whose `use` is not `sig`, or whose `key_ops` omits `verify`, is never a candidate (RFC 7517 §4.3) |
| `crit` | unknown critical header extensions are rejected by PyJWT, pinned by regression |
| claim types | `exp`, `nbf` and `iat` must be numbers as RFC 7519 defines them — PyJWT would otherwise coerce a string through `int()` |
| size | a bearer over 8 KiB is refused before decoding, since an `Authorization` header is not bounded by the MCP body limit |
| `iss` | exact string comparison against configuration |
| `aud` | must contain the configured resource; a string or a list, and the token may legitimately have other audiences too |
| `sub` | present, a string, non-empty |
| `exp` / `nbf` | through the library's registered-claim validation, no leeway, no invented maximum age |
| `typ` | only under the `rfc9068` profile, which also requires `client_id`, `iat` and `jti` |

Scopes come from the standard space-delimited `scope` claim, deduplicated and
order-preserving; a provider-specific permissions claim is deliberately not
merged in, because two vocabularies quietly unioned is how a permission granted
in one system becomes a scope in another. `client_id` (or `azp`) is recorded as
the OAuth *client* and is never treated as human identity — the tenant is still
derived from issuer and subject.

**Only four values cross into the request context**: the issuer, the subject, the
scopes and the expiry. Not the raw JWT — nothing in the SDK's resource-server
path reads it, so a placeholder goes there instead. Not the decoded payload
either: an access token routinely carries a name, an email and an organization,
and none of that belongs in a ContextVar later code can read.

### Fetching keys

Only the configured `jwks_url`. **Redirects are disabled** — a JWKS endpoint that
moves is a deployment change, not a runtime hop, and following one would let
whoever controls that hostname supply keys. Normal system CA verification, never
relaxed. Bounded timeouts, a response-size ceiling checked before parsing, a key
count limit, and a content-type check.

One HTTP client for the process, created on first use and closed by the
application lifespan. It is deliberately *not* a provider client: a provider
client's retry, quota and metric semantics mean something else entirely.

Keys are cached, and **the cache has a finite lifetime** — five minutes, matching
PyJWT's own. Two separate controls, for two different threats:

| Control | Default | Bounds |
| --- | --- | --- |
| `cache_lifetime_seconds` | 300 s | how long a **revoked** key keeps being accepted |
| `minimum_refresh_interval_seconds` | 30 s | how often attacker-chosen key ids can trigger a fetch |

The lifetime is the one that makes revocation mean anything. When an
authorization server retires a compromised key it disappears from the JWKS
document — but a resource server that kept trusting an already-known `kid` would
accept freshly forged tokens for as long as the process lived, and token `exp`
does not help because whoever holds the private key mints new ones. So an expired
set is **discarded**, not merely refreshed-before-use: after expiry the key is
simply not there, and a failed refresh leaves nothing to fall back on.

**An expired cache plus an unreachable identity provider fails closed.** There is
no stale-key grace period. Availability is not worth indefinite trust in a key
that may have been revoked precisely because it was compromised. Only a document
that fetched *and parsed* starts a new freshness window, so a malformed refresh
neither corrupts working keys nor extends the life of old ones.

An unknown `kid` triggers **one** coordinated refresh that concurrent requests
share, and so does expiry — a burst at either produces one fetch, and everyone
waiting sees the same atomically validated replacement. The floor's cost is
stated rather than hidden: a key published immediately after a fetch becomes
visible on the next fetch it allows. In practice authorization servers publish a
new key before signing with it, so a pre-published next key works from the cached
set with no fetch at all. A lifetime shorter than the floor is refused at
construction rather than left ambiguous.

**Startup contacts no identity provider.** Keys arrive with the first
authenticated request, so `/health` keeps answering during a brief IdP outage —
deployment liveness is not identity-provider reachability — while authentication
fails closed until keys can be loaded. `/health` and the RFC 9728 metadata
endpoint never trigger a JWKS fetch at all.

Externally every failure is the same `401`. Internally the categories are
distinguished for logs — `invalid_signature`, `issuer_mismatch`,
`audience_mismatch`, `token_expired`, `key_not_found`, `jwks_unavailable`,
`malformed_jwks` and the rest — and never carry a claim, a key, a hostname or a
raw token. No JWT is logged at any level.

### Example authorization server configuration

TI Recon bundles no identity provider and issues no login token. Any OAuth 2.1
server that issues signed JWT access tokens works; **Auth0 is what the next phase
will use for a staging acceptance test, and it is not tested yet.** There is no
`Auth0TokenVerifier`, no vendor settings class and no vendor branch — the code
contains no provider name at all.

For that staging run, the authorization server needs:

| Setting | Value |
| --- | --- |
| API identifier / audience | the **exact** TI Recon MCP resource URL |
| API permission | `ti-recon:investigate` |
| signing algorithm | RS256 initially |
| JWT profile | RFC 9068 (`at+jwt`) is what the next phase will configure via `TI_RECON_AUTH_TOKEN_PROFILE=rfc9068`; the generic profile also works |
| resource parameter | must accept RFC 8707 `resource`, which MCP clients send |
| client registration | prefer CIMD; DCR still works but is deprecated in MCP 2026 |

TI Recon depends on none of that machinery. It publishes `authorization_servers`
in its protected-resource metadata and Claude Code arranges registration with
that server directly, so the resource server stays registration-mechanism
neutral.

### Building one

```python
app = build_remote_http_app(
    runtime,  # build_remote_runtime(auth=...)
    config=RemoteHttpConfig(
        resource_url="https://mcp.example.com/mcp",
        issuer_url="https://idp.example.com",
        allowed_hosts=("mcp.example.com",),
    ),
    auth=RemoteAuthConfig(...),  # issuer, resource, tenant key
    delegate=your_token_verifier,  # required; there is no default
)
```

`delegate` has no default on purpose. The only verifiers constructible without an
identity platform are the three that must never exist — a static-token verifier,
an unsigned-JWT verifier, and a "development" verifier reachable from
production — so the factory refuses to invent one.

### One canonical resource URL

`https://mcp.example.com/mcp`, stated once, drives four things that must agree
byte for byte: the audience the verifier requires, `AuthSettings`, the RFC 9728
metadata, and the `resource` a client sends. `build_remote_http_app` refuses to
build if the verifier's expected resource or issuer differs from the published
one — advertising one resource while accepting tokens for another is the
confused-deputy shape, and it is exactly the mistake that survives review because
both halves look right on their own.

Trailing-slash identity is exact. `/mcp` and `/mcp/` are two OAuth resources, and
neither is normalized into the other.

### Configuration fails closed

Refused at construction: an empty issuer or resource, a resource that is not
HTTPS, a resource whose path is not exactly `/mcp`, an empty host allowlist, a
wildcard host, a wildcard origin, a zero concurrency limit, and a missing
delegate. There are no permissive production defaults.

### Scope

One scope for the whole resource: **`ti-recon:investigate`**.

`provider_status` is *less* privileged than an investigation and reveals only the
caller's own configuration, so a second scope would buy no meaningful least
privilege — nobody wants a token that can list their own setup but not use it —
while costing a step-up flow and a second consent screen. The vocabulary is
versioned in `REMOTE_SCOPES` so a later privilege boundary (a write surface, say)
can be added beside it rather than by redefining this one.

Scope is enforced by the SDK's middleware, before any handler runs. No tool
contains a scope check; one policy, in one place.

### Cheap checks come first

`build_remote_http_app` returns a `RemoteHttpApp` — a thin ASGI gate over the
SDK's Starlette application — rather than the SDK application itself. That is
not decoration: the order matters, and the SDK cannot arrange it from inside.

The SDK installs `AuthenticationMiddleware(BearerAuthBackend)` as Starlette
*application* middleware, so it wraps the whole routing table, while
`TransportSecurityMiddleware` runs inside the Streamable HTTP transport handler —
after routing and after `RequireAuthMiddleware`. Measured before the gate
existed:

| request | status | verifier calls |
| --- | --- | --- |
| bad `Host` + invalid bearer | 401 | **1** |
| bad `Origin` + invalid bearer | 401 | **1** |
| `text/plain` POST + invalid bearer | 401 | **1** |
| `GET /health` + garbage bearer | 200 | **1** |
| metadata + garbage bearer | 200 | **1** |

None of those leaked anything — the eventual answers were correct. But all of
them let unauthenticated traffic drive the most expensive thing in the request
path, which for an introspection-based delegate is a network call to the identity
provider. And the first three never reached the Host check at all: the invalid
bearer answered first, so a rebinding probe was being told "bad token" rather
than "wrong host".

The gate hoists the cheap checks in front of the whole SDK application. All five
rows are now **0**.

It parses no `Authorization` header, reads no bearer, understands no scope,
builds no `WWW-Authenticate` and generates no metadata — OAuth stays entirely
inside the SDK. It decides only whether a request is *eligible* to reach the
authenticated application.

It also invents no Host or Origin rules. Validation is delegated to the SDK's own
`TransportSecurityMiddleware`, built from the same `RemoteHttpConfig` the inner
transport receives: **one configuration, two enforcement points, never two
policies.** The inner check stays enabled as defence in depth, so a mistake in
the gate cannot silently disable the SDK's protection — a test drives the inner
application directly to prove it still refuses an untrusted Host.

### The flow a client sees

| Step | Result |
| --- | --- |
| `POST /mcp` with no token | `401` + `WWW-Authenticate: Bearer error="invalid_token", resource_metadata="…"` |
| `GET /.well-known/oauth-protected-resource/mcp` | resource, `authorization_servers`, `scopes_supported`, `bearer_methods_supported` — no secret |
| Valid token, wrong scope | `403` + `error="insufficient_scope"` + `scope=` |
| Token for another resource, wrong issuer, no subject, expired | `401`, and no handler runs |
| Valid token | `200`, MCP result |

**One SDK behaviour worth knowing.** The spec says a server SHOULD include a
`scope=` parameter in the `401` challenge; the installed SDK emits it only on the
`403`. Clients have a defined fallback — the `scopes_supported` this server does
publish in protected-resource metadata — so this is an interoperability note
rather than a defect, and it is pinned by a test rather than patched. Revisit only
if real Claude Code OAuth fails.

**A second one, since fixed.** Starlette's authentication middleware sits outside
the route, so the bearer used to be verified before the Host check. That is what
the preflight gate above now prevents; the SDK behaviour is unchanged and still
visible if the inner application is driven directly.

### The remote tool surface

| Profile | Tools |
| --- | --- |
| stdio | `investigate_observable`, `investigate_file`, `provider_status` |
| remote HTTP | `investigate_observable`, `provider_status` |

**`investigate_file` is absent remotely, not hidden.** Its `path` argument names a
file on the machine running the server: over stdio that is the analyst's own
workstation, over HTTP it is somebody else's server — so the tool would stop being
file analysis and become an authenticated arbitrary-read primitive. Leaving it
registered and merely undocumented would still list it and still let a
hand-written `tools/call` reach a path. It is not registered, so the call fails as
an unknown tool.

A remote analyst with a file hashes it locally and submits the SHA-256, or uses
the local stdio server. There is no upload, no multipart, no remote sample storage
and no submission.

Both schema resources — `ti-recon://schema/request` and
`ti-recon://schema/report` — are served over the same authenticated endpoint. No
credential state, provider payload, graph, execution state or token claim is
exposed as a resource.

### Transport security is explicit

```python
TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["mcp.example.com"],
    allowed_origins=[],  # or the exact browser origins you serve
)
```

Always passed, never left to the default. The SDK auto-enables rebinding
protection *only* for a loopback host and otherwise falls back to protection
**disabled** for backwards compatibility — so a production hostname with no
settings is silently unprotected.

Host: exact configured authority, narrow by default. `*` and any leading-wildcard
value are refused at construction, because a wildcard disables the protection
while appearing to configure it. An unlisted Host is `421`.

Origin: **absent is allowed**, which is the ordinary Claude Code shape — non-browser
clients send none, and the transport permits that. A *present* origin must be in
the allowlist, which is empty by default; an unlisted one is `403`. Never `*`.

`Content-Type` must be `application/json` on POST. Body limit is the SDK's own
4 MiB default, recorded rather than chosen — Task 24 tunes it together with the
ingress.

### Nothing is derived from a request header

Not the canonical resource URL, not the issuer, not the audience, not the host
policy. `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded` and `Origin`
are never read for a security decision, so the app needs to trust no proxy header
and there is no proxy middleware to configure. TLS terminates at the ingress; the
internal bind may be plain HTTP, and the public scheme is configured rather than
sniffed.

### Lifespan ownership

The gate is a raw ASGI wrapper, not a Starlette `Mount`. Lifespan events pass
straight through to the SDK application, which keeps owning the Streamable HTTP
session manager — `run()` refuses a second call on one instance, so ownership has
to stay in one place.

Two tests hold that down: one drives several requests plus a health probe through
a single lifespan, and one builds the app with *no* lifespan and asserts `/mcp`
raises while `/health` still answers. The second matters most — without it, every
other test here could be proving something about a fixture that starts a session
manager a real ASGI server would not.

### Sessions and protocol eras

`stateless_http=True`, `json_response=True`.

Every 2026-07-28 request is self-contained already — no `initialize`, no
`Mcp-Session-Id`. The flag additionally stops a handshake-era client creating a
server-side transport session, and both eras arrive on the same protected path.
TI Recon needs no sampling, elicitation, resource subscription or resumable SSE,
so a session would carry nothing — and would be process-local state a future
second worker could not see.

### One investigation per tenant

An authenticated caller can open as many concurrent HTTP requests as they like,
and a DEEP investigation with pivot enrichment is the most expensive thing this
system does. `TenantInvestigationLimiter` allows **one active
`investigate_observable` per tenant per process**.

A refusal, not a queue: a caller told "try again" still has a working service,
while a caller behind an unbounded backlog has a slow one and the server is
holding memory for requests nobody is waiting on. The slot is released on
completion, on error and on cancellation — cancellation most of all, because a
client going away mid-investigation is ordinary, and a leaked slot would lock an
analyst out for the life of the process.

`provider_status` never takes a slot: it contacts nothing, and blocking it would
remove the diagnostic exactly when somebody is working out why their investigation
is stuck. The limiter key is the pseudonymous tenant id and nothing else, and
entries are dropped when a tenant goes idle.

This is not Task 6's provider concurrency, which bounds calls to one provider
under one credential and is unchanged. Local stdio has no limiter at all — one
process, one analyst, one conversation, nothing to collide.

### `/health`

`GET /health` -> `{"status": "ok"}`. Answered by the gate, before the SDK
application is entered.

That placement is the point. It was an SDK custom route, which the SDK documents
as unauthenticated — but a custom route still sits *behind* the app-level
authentication middleware, so `Authorization: Bearer garbage` on a public
endpoint drove a token verification. Served from the gate there is no middleware
to sit behind: no `AuthenticationMiddleware`, no `BearerAuthBackend`, no
verifier, no `RemotePrincipalSource`, no credential resolver, no executor. The
test uses a verifier that *raises* if called, so this is a proof about the code
path rather than about a counter.

It still respects the transport policy, because the gate applies globally: an
allowed Host with no Origin or an allowed one gives `200`, an untrusted Host
gives `421` and an untrusted present Origin gives `403`. A `GET` carries no JSON
content-type requirement, and a write method gives `405`.

It reveals nothing about the deployment: no version, issuer, resource URL,
provider count, tenant count, uptime or cache state. Each of those is a small
gift to somebody deciding whether this host is worth attacking, and none of them
helps a load balancer.

Deliberately **not** called readiness. Task 18 owns that word for whether the
intelligence collected was adequate, and one term meaning two things in one system
is how somebody eventually acts on the wrong one. A deployment readiness probe
waits for Task 24, where there will be a credential backend whose reachability is
worth reporting.

Tests enumerate both routing tables — the gate's `public_paths` and the SDK
application's `routes` — and assert they are exactly `/health` and
`{/mcp, /.well-known/oauth-protected-resource/mcp}`, so a future route cannot
quietly join the public set.

### The metadata endpoint is public, and now verifier-free

RFC 9728 protected-resource metadata is unconditionally public — a client reads
it precisely *because* it was refused — so a bearer sent there is meaningless.
The SDK verified one anyway, for the same app-level-middleware reason.

The gate drops the `Authorization` header on that exact path before handing the
request onwards. That is enough to skip verification and changes nothing else:
the route was unauthenticated either way and still answers with the SDK's own
document, byte for byte. **Nothing is copied, rebuilt or re-routed** — the
metadata stays the SDK's, and this repository builds no OAuth document of its
own.

The path comparison is exact and fails in the safe direction: matching too
broadly would strip a bearer from a *protected* path, which becomes a `401`
rather than access. A test pins that `/mcp` still receives its bearer.

### No authorization server

`/authorize`, `/token`, `/register`, `/revoke`, `/login` and
`/.well-known/oauth-authorization-server` all return `404`. `auth_server_provider`
is never supplied, so they are absent rather than merely unimplemented. TI Recon
verifies tokens an external authorization server issued and never becomes one; it
builds no user database, no login page, no password reset, no MFA and no client
registration. Client registration — DCR or CIMD — belongs to the external
authorization server.

The code names no identity provider. Auth0, Entra, Okta, Keycloak and Cognito are
all *examples* a deployment may choose; none is a requirement, and none appears in
`src`.

## One process, for now

Task 6's cache, cooldown, quota and single-flight stores are process-local, and so
is the tenant limiter. **Remote deployment is single-worker.** This is a
correctness requirement rather than a performance note: four workers would enforce
every one of those four times independently, letting four analysts' identical
questions become four provider calls against metered APIs and letting one analyst
hold four investigation slots.

No `--workers` option exists because no runnable entry point exists. A deployer
running the ASGI app through their own server must run exactly one worker until
Task 24 gives that state a shared backend.

## Still to come

**Task 22, next phase — staging IdP acceptance.** Point the process at a real
authorization server, complete a Claude Code OAuth login end to end, and confirm
discovery, consent, token audience and scope against a live tenant. Nothing in
that flow has been exercised against a real identity provider yet.

**Task 23** — secure provider credential management: durable encrypted per-user
storage, an authenticated out-of-band provisioning path, rotation, revocation and
audit.

**Task 24** — production packaging and operations: container, ingress, worker
policy and shared execution state, rate limiting, timeouts, metrics and tracing.

# TI Recon — Per-User Provider Credential Management

> Task 4. Describes `src/ti_recon/credentials/`.
>
> The only secret backend implemented is in-memory and explicitly **not for
> production**. A real vault is a later task.

## 1. Threat model

Two properties must hold, and both are tested:

1. **A provider credential never leaves the credential layer as a value.**
   It must not appear in Claude prompts, the Claude Skill, MCP arguments, git,
   logs, exceptions, serialized provider results or serialized models.
2. **User A can never obtain user B's credential**, by any route the layer
   exposes.

The second matters more than it looks. TI Recon is multi-tenant by design —
each analyst brings their own API keys — and a paid VirusTotal key is a
credential worth stealing, quota worth burning, and an audit trail worth
poisoning.

## 2. Layers

```
CredentialResolver     resolve(authenticated_user_id, provider_id) -> CredentialMaterial
        |
CredentialManager      create / replace / disable / disconnect / metadata reads
        |
ConnectionRepository   ProviderConnection records, always user-scoped
SecretStore            secret material, keyed by (owner, key)
```

Only `CredentialMaterial` ever holds a secret, and only inside a `SecretStr`.

## 3. Vocabularies

`AuthType`: `api_key`, `bearer_token`, `auth_key`, `oauth`.

`auth_key` is separate from `api_key` because some providers (the abuse.ch
family) use an `Auth-Key` header shared across several services — a different
credential-grouping shape, not just a different header name.

`CredentialStatus`: `active`, `invalid`, `expired`, `revoked`, `disabled`,
`unknown`.

`PolicyStatus`: `allowed`, `restricted`, `blocked`, `pending_approval`,
`unknown`.

These are three independent axes, and a test asserts `CredentialStatus` shares
no value with `ProviderRunStatus`:

| Axis | Question | Where |
|------|----------|-------|
| `CredentialStatus` | is the key itself usable? | credential layer |
| `PolicyStatus` | does policy permit this provider? | credential layer |
| `ProviderHealth` | is the provider up? | provider layer |
| `ProviderRunStatus` | how did this one call go? | investigation |

Collapsing any two would make "the provider is down" and "your key was revoked"
indistinguishable to an analyst — the difference between waiting and acting.

## 4. Secret indirection

```python
class SecretRef(FrozenTiReconModel):
    owner_user_id: Identifier
    key: str
```

`ProviderConnection` carries a `SecretRef`, never the secret. A model validator
rejects any connection whose `secret_reference.owner_user_id` differs from its
`user_id`, so a connection cannot be constructed pointing at another user's
secret.

The owner is part of the reference rather than a separate argument. A store
lookup therefore cannot be performed without naming whose secret is wanted,
which removes the bug class where a caller passes a bare key obtained from
somewhere else and reads a foreign credential.

### `ProviderConnection`

`id`, `user_id`, `provider_id`, `credential_group`, `auth_type`,
`secret_reference`, `status`, `policy_status`, `label`, `metadata`,
`created_at`, `updated_at`, `last_validated_at`, `last_used_at`, `expires_at`.

`metadata` is guarded by the same credential-like-key rejection used for
`Evidence.attributes`.

`is_usable` is true when the status is not one of `invalid`, `expired`,
`revoked`, `disabled`; policy is `allowed` or `restricted`; and `expires_at` has
not passed. `unknown` counts as usable — a freshly added key has not been
validated, and the way to find out whether it works is to use it.

### `CredentialMaterial`

The resolved credential, frozen, held only for the duration of a call:
`connection_id`, `user_id`, `provider_id`, `credential_group`, `auth_type`,
`secret: SecretStr`.

Reading the secret requires `material.reveal()` — a deliberately conspicuous
name, so every place that handles a raw credential is one `grep` away.

Tests assert the secret is absent from `repr()`, `str()`, f-strings,
`model_dump()`, `model_dump_json()`, exception text, `ValidationError` text and
`logging` output. (A `pickle` of the model does contain it; that boundary is
documented by a test rather than left implicit.)

The `ValidationError` case is why every TI Recon model sets
`hide_input_in_errors=True`: pydantic otherwise embeds rejected input in the
error message, so a validation failure on a credential field would print the
credential.

## 5. `SecretStore`

```python
class SecretStore(Protocol):
    async def put_secret(self, ref: SecretRef, secret: SecretStr) -> None: ...
    async def get_secret(self, ref: SecretRef) -> SecretStr: ...
    async def delete_secret(self, ref: SecretRef) -> None: ...
    async def exists(self, ref: SecretRef) -> bool: ...
```

There is deliberately no "list all secrets" and no "get by bare key": either
would make cross-tenant leakage a one-line mistake.

`get_secret` raises `SecretNotFound` both when the reference does not exist and
when it exists under a different owner, so the store cannot be used as an oracle
for what other users have configured.

### `InMemorySecretStore` — NOT FOR PRODUCTION

Process-local, unencrypted, lost on restart, not shared between workers, not
audited. It exists so the credential layer can be developed and tested without
standing up a vault. It carries `is_production_ready = False` for callers that
refuse to boot on a development backend, and its `__repr__` reports only an
entry count — never keys, owners or values.

No HashiCorp Vault, AWS, Azure or GCP backend is implemented. This Protocol is
the seam one will slot into.

## 6. `ConnectionRepository`

Every method takes `user_id`. There is no `get(connection_id)` and no global
listing — an unscoped read is the shape cross-tenant leaks take, so the
interface does not offer one.

`InMemoryConnectionRepository` (also **not for production**) enforces at most
one connection per `(user_id, credential_group)`, which keeps resolution
deterministic: there is never a question of which of a user's two keys for the
same provider should be used.

## 7. `CredentialManager`

| Operation | Notes |
|-----------|-------|
| `create_connection` | stores the secret, returns metadata; new credentials start `unknown`, not `active` |
| `replace_credential` | safe rotation (below) |
| `disable_connection` | marks unusable, keeps the secret |
| `set_status` | records a validation outcome; `active` stamps `last_validated_at` |
| `record_usage` | stamps `last_used_at` |
| `disconnect` | removes the connection *and* its secret |
| `get_connection` / `list_connections` / `find_connection_for_provider` | metadata only |

Passing another user's `connection_id` raises `ConnectionNotFound` — identical
to a nonexistent id, so the error cannot be used to probe other users'
configuration. `disconnect` returns `False` rather than raising.

### Safe replacement flow

```
write new secret  ->  switch reference  ->  remove old secret
```

Any other order leaves a window in which the connection points at a secret that
is already gone. If the reference switch fails, the newly written secret is
deleted so no orphan is left behind; the same rollback applies if
`create_connection` cannot save its record.

Rotation resets `status` to `unknown` and clears `last_validated_at`: the old
validation result says nothing about the new key.

## 8. Credential resolution

```python
await resolver.resolve(
    authenticated_user_id=...,  # keyword-only, no default
    provider_id=...,
    credential_group=None,  # defaults to the provider's group
)
```

The parameter is named `authenticated_user_id` on purpose: it must come from the
request's verified identity, never from a caller-supplied argument, an MCP tool
parameter, or anything a model could influence. A test asserts the parameter is
keyword-only with no default on every resolver entry point.

Failure modes: `CredentialNotConfigured`, `PolicyDenied`, `CredentialUnusable`.

`has_credential(...)` answers "is this provider worth calling?" without
resolving — and therefore without touching — the secret.

## 9. Credential groups

Most providers need their own credential. The abuse.ch services share one:

```python
ABUSE_CH_GROUP = "abuse_ch"
CREDENTIAL_GROUP_MEMBERS = {
    "abuse_ch": {"threatfox", "urlhaus", "malwarebazaar"},
}
```

`credential_group_for(provider_id)` returns the group, defaulting to the
provider id itself, so callers never need a special case for the common path.
One stored `Auth-Key` therefore serves all three services — and stays scoped to
the user who stored it.

This is grouping configuration, not a provider integration: no API host,
endpoint or payload shape appears in the module.

## 10. Tested isolation guarantees

From `tests/unit/test_credentials_isolation.py`:

- A and B each resolve only their own key, for a plain provider and for the
  abuse.ch group.
- A cannot read B's secret even holding B's reference key string (the owner
  scope makes it unreadable).
- A cannot read, list, rotate, disable or delete B's connection.
- Deleting or rotating A's credential leaves B's untouched.
- "B has a credential, A does not" produces a byte-identical error to "nobody
  has a credential".
- Error text never contains another user's secret or user id.
- A `ProviderConnection` cannot be constructed pointing at a foreign secret.

## 11. Not implemented

Production secret backends (Vault, AWS/Azure/GCP), credential persistence,
encryption at rest, key-rotation scheduling, audit logging, OAuth token refresh,
and credential validation against live provider APIs. The `AuthType.OAUTH`
member exists in the vocabulary; no OAuth flow is implemented.

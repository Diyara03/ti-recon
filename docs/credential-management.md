# TI Recon — Per-User Provider Credential Management

> Task 4.
>
> **Status at this commit:** placeholder. The credential layer lands in a later
> commit of this series (`feat(credentials): ...`), and this document is filled
> in alongside it. Nothing described here is implemented yet.

Planned contents:

- credential model (`ProviderConnection`, `CredentialMaterial`) and statuses
- secret-reference indirection and secret-leak prevention
- `SecretStore` abstraction and the development-only in-memory implementation
- credential manager lifecycle and safe replacement flow
- user-scoped credential resolution and cross-user isolation guarantees
- credential groups (e.g. shared abuse.ch Auth-Key)

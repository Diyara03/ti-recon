# Provider artifacts

> Task 8. Describes `src/ti_recon/artifacts/`.

## What an artifact is

A bounded copy of something a provider already stored: a screenshot, a DOM
snapshot, a response body. TI Recon keeps them so a forensic finding can be
re-examined against the thing it came from — "this is the script we extracted
that exfiltration URL from" — and for no other reason.

`RawEvidenceReference` (Task 3) is provenance only: a storage key, a digest, a
size. Something has to own the bytes, and that is this subsystem.

## Provider-neutral by design

Nothing in `artifacts/` mentions any vendor. Any provider that archives what a
browser or a sandbox saw produces the same shape, and a subsystem that knew
about one vendor would have to be rewritten for the second.

## Isolation

Every operation takes an `ArtifactScope` (`user_id` + `investigation_id`), and a
lookup with the wrong scope returns `None` — indistinguishable from a missing
id, because "that exists, but not for you" is itself a disclosure.

```python
store.get(other_scope, artifact_id)      # -> None
store.content(other_scope, artifact_id)  # -> None
```

## Paths are never provider text

A storage key is:

```
sha256(user_id \0 investigation_id)[:32] / <kind> / <content sha256>
```

and `StoredArtifact` rejects any key it did not derive. Provider text therefore
has no influence on where bytes live: a response named `../../etc/passwd` is
just another body with a digest.

The scope is hashed rather than spelled out for two reasons. An analyst id may
be an email or contain any character at all, and interpolating that into a path
is how traversal bugs happen. And a storage key gets logged — a partition that
reads back as somebody's identity is a small privacy leak in every line that
carries it.

## Bounds

| Limit | Default |
|---|---|
| `max_artifact_bytes` | 8 MB |
| `max_total_bytes` per investigation | 64 MB |
| `max_artifacts_per_investigation` | 200 |

A page under investigation chooses how big its own DOM is, so an unbounded store
is a memory-exhaustion primitive handed to the adversary. Providers apply their
own caps when fetching; these are the second line, so a bug or a new provider
cannot skip them. Neither limit can be set to zero.

`ArtifactTooLarge` and `ArtifactBudgetExceeded` describe the limit and never
what is in storage.

## Content addressing and truncation

Content is addressed by digest, so the same phishing kit retrieved from forty
scans is one entry — which is also what makes "these forty pages served the same
script" cheap to see.

`truncated` travels with the metadata rather than being inferred from a size.
Half a screenshot is not a screenshot, and half a script may parse into findings
that are not in the real file. `is_usable` is false for a truncated or empty
artifact.

## Metadata vs bytes

`StoredArtifact` is metadata only and is safe to log, serialize and attach to
evidence. Bytes come back only from `content(scope, artifact_id)`, and only to
the owning scope. `to_raw_reference()` produces the Task 3 provenance pointer so
a piece of evidence can say where it came from without carrying the payload.

## Storage backend

`InMemoryArtifactStore` is single-process and lost on restart, like every other
store in this codebase so far. Nothing is written to disk, which also means no
provider-supplied text ever reaches a filesystem. A durable backend can be
swapped in behind the `ArtifactStore` protocol without relaxing any of the
guarantees above.

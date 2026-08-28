# Acknowledged breaking changes to the frozen contract

`task openapi:breaking` fails the build on any breaking change to
`specs/001-agent-manager-hub/contracts/openapi.yaml`, because the CLI ships separately from the hub
and cannot be redeployed in step with it. That gate is right, and it must stay live.

This file is the narrow exception. A breaking change is permitted only when it appears here with a
justification, so the first legitimate break does not force anyone to disable the gate wholesale —
which is the failure this file exists to prevent. Anything breaking and unlisted still fails.

**The format is machine-read.** One entry per breaking change, and the fenced `id` line must be the
`<changeText>|<path>` pair exactly as `openapi-changes` reports it. Add the entry in the same commit
as the change; a stale entry is as bad as a missing one, because it silently permits a future break
that happens to match.

Removing an entry once every client has caught up is not just housekeeping: it restores the gate for
that surface.

---

## `agents-md` removed from the `targets` enum

```id
property_removed|$.paths['/v1/profiles/{slug}/revisions/{revision}'].get.responses['200'].content['application/json'].schema.properties['targets'].items
property_removed|$.paths['/v1/sync'].post.requestBody.content['application/json'].schema.properties['targets'].items
```

**Why it is breaking:** a client built against the old document has `agents-md` in its generated
enum and may send it to `POST /v1/sync`. The hub will now refuse that value.

**Why it is permitted:** no client has shipped. The only client is `amctl`, which is being written
in this repository and has never had a release; its own `agents-md` target refused to construct
from the first commit that mentioned it, because research gate R2 found the convention unresolvable
as an install target (`specs/002-agent-manager-cli/plan.md`, R2). The value described a capability
that never existed on either side.

**Why it was not left in place:** a value the API declares and refuses is worse than one it does
not declare. It reads as supported to anyone generating a client, it can still be written to
`sync_target` directly, and nothing would then be able to render that row.

**What restores it:** a design for composing N packages into delimited, individually prunable
regions of one shared markdown file, plus a per-user location for that file to live in. Until both
exist, the enum value would be a promise the tool cannot keep. Reintroducing the value is an
additive, non-breaking change and another migration.

---

## The mechanism was checked, not assumed

A rubber-stamp file that acknowledges everything is worse than no file, so the matching was
verified with three negative controls when it was written. Each one was run and each one fired:

| Control | Expected | Observed |
|---|---|---|
| One of the two `id` lines deleted | fails on exactly that one, still acknowledges the other | `1 acknowledged`, then `BREAKING … /v1/sync …`, exit 201 |
| This file removed entirely | fails on both | both listed as `BREAKING`, exit 201 |
| Both `id` lines replaced with `property_removed\|.*` | matches nothing — the pattern is not a pattern | both listed as `BREAKING`, exit 201 |

The third is the one that matters. `grep -Fxf` compares whole lines literally, so `.*` is a
literal string and not a wildcard. An unanchored or regex-interpreted match would have made every
future `property_removed` acknowledgeable by one entry, which is the failure mode this table exists
to rule out. Re-run the controls if the matching in `Taskfile.openapi.yaml` is ever touched.

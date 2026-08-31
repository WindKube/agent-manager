# Phase 1 — Data model: a lightweight local identity provider and a web UI with no placeholder screens

**Feature**: `003-usable-web-ui` · **Date**: 2026-08-31

## There is no schema change

No new table, no new column, no new enum value, no index, no migration, no `atlas.sum` churn.
Feature 001's T013–T017 migrated the whole relational model up front, and most of it has been
sitting unused. This document's job is to say which parts wake up, what reads them, and which
two state machines this feature drives that nothing could reach before.

A task that proposes a migration in this feature should be treated as a design error until it
argues otherwise in review.

---

## Tables that stop being write-only or unused

| Table | State today | What this feature does with it |
| --- | --- | --- |
| `session` | Resolved on every api request by `auth.Sessions.Resolve`. **Nothing ever inserts a row.** | Sign-in inserts; sign-out expires. `commands.Login` and `commands.ExpireSession` already implement both and are simply unreachable. |
| `identity` | Same — read by the session join, never written outside tests. | Upserted on first sign-in (JIT provisioning, FR-109). |
| `group_role_map` | Read by the session-resolve statement. Seeded only in tests. | Read on every request as today; gains CRUD from the Organization screen (US7). Its rows are what make the two local users differ (SC-104). |
| `scan`, `scan_check` | Migrated. No writer exists. | Written by the scanner worker; read by the Scanner screen's checks matrix and by the catalog's status column. |
| `finding`, `finding_evidence` | Migrated. No writer exists. | Written by the scanner; read by the Scanner screen's list and detail pane; counted by the sidebar's scanner badge. |
| `override` | Migrated. No writer exists. | Written when a reviewer approves a flagged version with a note; read by the Scanner screen's "active overrides, nearest expiry" figure and by profile resolution's gate logic. |
| `audit_event` | **Written** by every existing command; append-only by revoked grant. Never read. | Gains its read path and full-scope export (US4). Gains rows for sign-in and sign-out. |
| `org_policy` | Singleton row, `check (id = 1)`. Read by resolution. No write path. | Written by the Organization screen; each toggle must change downstream behaviour, not just its own row. |
| `category` | Read at registration. No write path. | Curated from the Organization screen with per-category counts. |
| `profile`, `profile_entry`, `revision`, `membership`, `sync_target` | Read by `queries.ReadableProfiles` and `queries.RevisionLockfile` for the CLI. No write path. | Gain the curation and publishing writes the Profiles screens need (US5). |
| `device_authorization` | Written and polled by the device endpoints; the CLI drives them. | Gains the browser approval transition (US6). |
| `fetch_attempt` | Written by the fetcher. Never read. | Read by the Storage screen's "recent fetches with an outcome indicator". |
| `sync_event` | Written by `POST /v1/sync`. Never read. | Read for the catalog's use counts and the Storage screen's CLI read-cache figure. |

Two tables are genuinely untouched by this feature: `outbox` (the relay already drains it) and
`signature` (signature verification stays out of scope).

---

## State transitions this feature makes reachable

### A finding

```
                    ┌──────────────── reopened by a new scan ────────────┐
                    │                                                    │
   (scanner writes) ▼                                                    │
                  open ──── reviewer rejects ──────> rejected ───────────┘
                    │
                    └──── reviewer approves with note ──> accepted (+ override row, with expiry)
```

Both reviewer transitions are commands: they run in one transaction that writes the finding's
new state, the override row where one applies, and exactly one audit row. Neither is reachable
today because no finding exists and no screen offers the action.

The reopen edge is 001's US4 scenario 5 — a new finding on an approved version reopens it — and
it is driven by the scanner, not by a person.

### A device authorisation

```
   pending ──── approved in the browser by the requesting identity ────> approved
      │                                                                     │
      │                                                          CLI's next poll
      ├──── expires ────> expired (terminal, no token)                      │
      ├──── approved by a different identity ────> refused, stays pending   ▼
      └──── polled after consumption ────> refused                      consumed
```

The `pending → approved` edge is the one this feature adds; the rest exists and is tested. The
transition happens in one transaction and is single-use, which is what makes replay refusal
(001 FR-042) a property of the schema rather than of the handler's care.

### A browser session

```
   (no cookie) ──── sign-in completes ────> active ──── sign-out ────> expired
                                              │
                                              └──── expires_at passes ────> expired
```

`auth.Sessions.Resolve` already treats "unknown token" and "expired token" as one error
deliberately, so that a caller cannot learn whether a token ever existed. Sign-out expires the
row; it does not delete it, so a replay is indistinguishable from a token that never was.

**Role is not part of this state.** It is resolved from `group_role_map` on every request by the
existing statement, which is what makes FR-118 (a mapping change taking effect without
re-login) true by construction rather than by a cache-invalidation rule.

---

## What each new read path needs

Listed so the query layer can be written against a known shape rather than discovered
screen-by-screen. Every one of these is a read-only query in `internal/api/queries/`
(principle VIII) and free to use purpose-built SQL.

| Query | Reads | Notes |
| --- | --- | --- |
| Viewer | `session` → `identity` → `group_role_map` | Already one statement in `auth.Sessions.Resolve`. The operation returns what it resolved rather than re-querying. |
| Sidebar badges | `package` (visible), `profile` (readable), `finding` (open) | Three counts, one operation (R5). The open-finding count is served by 001 T017's partial index `(version_id) where state='open'`. |
| Scanner summary | `scan`, `override`, `version` | Scans in the period, quarantined count, active overrides with nearest expiry, median fetch-to-verdict. The median comes from `scan` and `fetch_attempt` timestamps. |
| Findings list | `finding` → `version` → `package` → `publisher` | Ordered by severity then recency. Paged. |
| Finding detail | `finding`, `finding_evidence`, `scan_check` | The full check matrix for the finding's scan, not only the failing check — 001 US4 scenario 2 requires every check that ran with its result. |
| Audit page | `audit_event` → `identity` | Ordered by `occurred_at desc`, served by 001 T017's index. Paged. |
| Audit export | the same, unpaged | Streamed, full current scope (001 FR-051). Must not materialise the result set. |
| Profile list | `profile`, `profile_entry`, `revision`, `membership` | Reuses the readable-set predicate `queries.Readable` already enumerates rather than filters (001 FR-044). |
| Profile detail | the above plus `version`, `scan`, `override`, `org_policy`, `sync_target` | Each entry's resolved version, its scan state, and what the gate does to it. The gate logic already exists for resolution; the screen must call it, not restate it. |
| Organisation | `org_policy`, `group_role_map`, `category` (+ counts) | Category counts join `package`. |
| Storage | `fetch_attempt`, `sync_event`, and the object store itself | Object count, compressed size, region, bucket settings via `bucket.As(&s3Client)` as 001's plan specifies. The screen reports what the bucket reports (001's assumption). |

---

## What each new write path needs

| Command | Writes | Audit row |
| --- | --- | --- |
| Sign-in | `identity` (upsert), `session` | `login`, source `web` |
| Sign-out | `session` (expire) | one row |
| Approve finding | `finding`, `override` | `approve` |
| Reject finding | `finding` | one row |
| Curate profile | `profile_entry`, `sync_target` | one row per saved change |
| Publish revision | `revision` (immutable, sequential) | `profile`, with the change summary |
| Share profile | `membership` | one row |
| Approve device | `device_authorization` | `login`, source `cli / <host>` |
| Save org policy / mapping / category | `org_policy`, `group_role_map`, `category` | one row each |

Every one of these is one transaction containing its domain writes and its audit write
(principle IV). SC-111 asserts the count delta is exactly one per action, extending 001's
SC-008 sweep to the actions this feature adds.

---

## Non-schema state this feature introduces

Two pieces of state that are deliberately *not* rows.

**The sign-in round-trip state** — the OAuth `state` value and the PKCE code verifier, plus the
return target. These live in a short-lived signed cookie scoped to the callback path, not in a
table, because the web role has no table and because their lifetime is one redirect. See
[contracts/auth.md](./contracts/auth.md).

**The local directory** — glauth's two users, two groups and one service account are a TOML
fixture in `deploy/local/`, not data. They are replaced wholesale by a real provider in any
deployment that is not a laptop. See
[contracts/local-identity.md](./contracts/local-identity.md).

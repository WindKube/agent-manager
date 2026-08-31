# Contract — the api operations this feature adds

**Feature**: `003-usable-web-ui` · **Date**: 2026-08-31

Five of the seven placeholder screens have no api behind them, so they cannot be built as
presentation work. This is the list, with each operation's authorisation, so the query and
command layers can be written and reviewed against a fixed surface.

**Constitution principle V governs all of it**: each operation is declared once as a typed huma
operation in `internal/api/operations.go`, emitted into the OpenAPI 3.1 document, and reached
from the web role through the `oapi-codegen` client. No request or response type is written
twice. `internal/web` never hand-rolls a call.

**Principle VIII governs the split**: every read below lands in `internal/api/queries/`, every
mutation in `internal/api/commands/`, and every mutation writes its audit row inside its own
transaction.

---

## Authorisation legend

| Mark | Meaning |
| --- | --- |
| **session** | Bearer session token, resolved by `auth.Sessions.Resolve`. Every existing operation works this way. |
| **session + role** | As above, and the resolved role must be sufficient. Insufficient role is a refusal, and the screen must not have offered the action (FR-126). |
| **role secret** | Authenticated by the shared secret between the web and api roles, not by a session. **One operation only.** |
| **device** | The RFC 8628 device-code pair. Unchanged from 001. |

---

## Identity

| Operation | Method · Path | Auth | Serves |
| --- | --- | --- | --- |
| `createSession` | `POST /v1/sessions` | **role secret** | Sign-in (US2) |
| `getViewer` | `GET /v1/viewer` | session | The sidebar's viewer chip |
| `deleteSession` | `DELETE /v1/sessions/current` | session | Sign-out |

`createSession` is the one operation in this system whose caller is a role rather than a person,
and it can mint a session for any subject. Its rules are in
[auth.md](./auth.md#the-session-minting-operation) and its justification is the sole row of the
plan's Complexity Tracking table. Two properties are load-bearing and easy to lose:

- **Refused when the shared secret is unset.** No default, no development bypass.
- **The response carries the session token exactly once** and it is never logged. This mirrors
  `commands.LoginResult`, whose comment already says so.

`getViewer` returns what `auth.Sessions.Resolve` already resolved on the request — display name,
email, role, and whether the identity maps to any role at all (FR-117). It does not re-query.

---

## Sidebar badges

| Operation | Method · Path | Auth | Serves |
| --- | --- | --- | --- |
| `getBadges` | `GET /v1/badges` | session | Every full page render |

Three counts scoped to the viewer: visible packages, readable profiles, open findings. One
operation rather than three because it is called on every full page render (research R5).
**Not** called on a datastar fragment update. No projection — if it measures slow, a badge is
dropped rather than a projection added (principle VIII).

---

## Scanner (US4)

| Operation | Method · Path | Auth | Serves |
| --- | --- | --- | --- |
| `getScannerSummary` | `GET /v1/scanner/summary` | session | The four headline figures of 001 US4 scenario 1 |
| `listFindings` | `GET /v1/findings` | session | The findings list, paged, filterable by state and severity |
| `getFinding` | `GET /v1/findings/{id}` | session | The detail pane: rule, explanation, evidence, **and every check that ran** |
| `acceptFinding` | `POST /v1/findings/{id}/accept` | session + role | Approve with a note; writes the override with its expiry |
| `rejectFinding` | `POST /v1/findings/{id}/reject` | session + role | Reject; the version stays quarantined regardless of gate |

`getFinding` returns the full `scan_check` matrix for the finding's scan, not only the failing
check. 001 US4 scenario 2 requires every check with a pass / fail / warn-count result, and a
detail pane that shows only failures cannot be told apart from one where nothing else ran.

`acceptFinding` and `rejectFinding` each write the finding's new state, the override row where
one applies, and exactly one audit row, in one transaction.

---

## Audit (US4)

| Operation | Method · Path | Auth | Serves |
| --- | --- | --- | --- |
| `listAuditEvents` | `GET /v1/audit` | session | The paged log: actor, kind, text, source |
| `exportAuditEvents` | `GET /v1/audit/export` | session + role | CSV of the **full current scope** |

`exportAuditEvents` streams. 001 FR-051 says the export covers everything in scope, not the
visible page, so it must not materialise the result set — the audit log is the one table designed
to grow without bound.

---

## Profiles (US5)

`GET /v1/profiles` and `GET /v1/profiles/{slug}/revisions/{revision}` exist from 001 and are
unchanged — the CLI depends on them.

| Operation | Method · Path | Auth | Serves |
| --- | --- | --- | --- |
| `getProfile` | `GET /v1/profiles/{slug}` | session | The detail screen: entries, resolved versions, scan state, the gate's effect |
| `createProfile` | `POST /v1/profiles` | session + role | |
| `updateProfileEntries` | `PUT /v1/profiles/{slug}/entries` | session + role | Float/pin per package |
| `updateProfileSharing` | `PUT /v1/profiles/{slug}/sharing` | session + role (Owner) | Members and groups at the four levels |
| `updateProfileTargets` | `PUT /v1/profiles/{slug}/targets` | session + role | Sync targets, which affect only what a client writes |
| `publishRevision` | `POST /v1/profiles/{slug}/revisions` | session + role (Maintainer+) | A new sequential immutable revision |

`getProfile` must show each entry's resolved version *and what the org gate does to it* by
calling the existing resolution logic, not by restating the gate rules in a query. Two
implementations of the gate is how 001 US5 scenarios 2–4 start disagreeing with what the CLI
actually syncs.

`publishRevision` writes an immutable numbered revision; the previous one stays readable
(001 US5 scenario 5). Republishing a revision number is refused, not overwritten (principle IV).

---

## Device approval (US6)

| Operation | Method · Path | Auth | Serves |
| --- | --- | --- | --- |
| `lookupDeviceCode` | `GET /v1/device/authorizations/{user_code}` | session | Show the requesting host and remaining validity **before** the viewer confirms |
| `approveDeviceCode` | `POST /v1/device/authorizations/{user_code}/approve` | session | The confirm action |

`POST /v1/device/authorize` and `POST /v1/device/token` are unchanged from 001.

Three refusals must be distinguishable to the viewer (001 FR-042): expired, unknown, and already
consumed. A single generic "invalid code" leaves a person retyping a code that will never work.
Approval by an identity other than the requester is refused — and is *not* one of the three
distinguishable messages, because telling an attacker which codes are real is worse than a
confusing error.

`lookupDeviceCode` reads the user code from the path, so the operation must not log its own path
parameter. The user code is a bearer-equivalent secret for the length of its validity.

---

## Organisation (US7)

| Operation | Method · Path | Auth | Serves |
| --- | --- | --- | --- |
| `getOrganization` | `GET /v1/organization` | session + role | Provider settings, policy, mappings, categories |
| `testIdentityConnection` | `POST /v1/organization/identity/test` | session + role | The connection test of 001 US7 scenario 1 |
| `rotateClientSecret` | `POST /v1/organization/identity/secret` | session + role | Rotate **without revealing the current value** |
| `updatePolicy` | `PUT /v1/organization/policy` | session + role | The toggles |
| `listGroupRoleMappings` … `deleteGroupRoleMapping` | `GET/POST/DELETE /v1/organization/mappings[/{id}]` | session + role | Mapping CRUD |
| `listCategories` … `deleteCategory` | `GET/POST/PATCH/DELETE /v1/organization/categories[/{id}]` | session + role | Vocabulary with counts |

Two rules that are easy to get wrong:

- **`getOrganization` never returns the client secret**, not even masked in a way that leaks its
  length. `rotateClientSecret` returns the new value once.
- **A policy toggle must change downstream behaviour, not just its row** (001 T100). The gate
  change affects the next resolution; signed-bundles refuses a version with no signature
  reference *and states it is unverified* (001 FR-048a); community-needs-review routes to a
  queue; the rescan toggle changes the periodic job. A test that asserts only the stored row
  passes while the feature does nothing.

Tags are **not** in this list. They are manifest-derived and never admin-editable
(001 US7 scenario 5), and an endpoint that could edit them would be the bug.

---

## Storage (US7)

| Operation | Method · Path | Auth | Serves |
| --- | --- | --- | --- |
| `getStorage` | `GET /v1/storage` | session + role | Every figure of 001 FR-053 |

Object count, compressed total, region, CLI read-cache hit rate, the key layout for `skills/`
and `profiles/`, the bucket's versioning / object-lock / encryption / write-access / retention
settings, and recent fetches with an outcome indicator.

Bucket settings come from the raw S3 client through `bucket.As(&s3Client)`, as 001's plan
specifies. **The screen reports what the bucket reports** — this system configures and surfaces
object lock and retention, it does not enforce them (001's assumptions), so a figure the bucket
declines to report is rendered as unknown rather than as a default.

---

## Operations deliberately not added

- **Anything writing package content.** Packages are fetched, never authored here (001, out of
  scope).
- **Anything editing tags.** Manifest-derived, permanently.
- **A session list or a remote sign-out.** Out of scope in the spec; it is a real feature and it
  is a later one.
- **An identity or group write path.** The hub reads the `groups` claim; the provider owns
  membership.
- **A rescan trigger on the Scanner screen.** The rescan policy toggle drives the periodic job;
  a manual button is new product capability, and this feature implements 001's specification
  rather than extending it.

---

## The contract test that already exists

001's T097 added a CI check that the generated OpenAPI document stays a **superset** of
`specs/001-agent-manager-hub/contracts/openapi.yaml`, which is scoped to the frozen
machine-facing surface the CLI depends on. Every operation above is additive, so that check
should keep passing untouched — and if it fails, the cause is that one of these operations
changed a shape the CLI reads, which is a defect in this feature rather than a stale
expectation.

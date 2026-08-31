# Implementation Plan: A lightweight local identity provider and a web UI with no placeholder screens

**Branch**: `003-usable-web-ui` | **Date**: 2026-08-31 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/003-usable-web-ui/spec.md`

## Summary

Three things, in this order, because each unblocks the next.

**First, the local identity provider.** Keycloak goes; Dex in front of glauth arrives. Research
R1 re-measured feature 001's R6 finding and confirmed it — Dex silently ignores `groups:` on a
static-password user — then measured what R6 never tried: Dex with an LDAP connector against
glauth emits per-user groups, in 268 MB and one second, against Keycloak's 730 MB and nine.
Dex has no equivalent of `KC_HOSTNAME_BACKCHANNEL_DYNAMIC`, so research R2 inverts the
browser/container URL split: the issuer becomes container-reachable and one new configuration
value names the browser-facing base for the single endpoint a browser touches. That deletes
`oidc.InsecureIssuerURLContext` from the local path — the swap removes a hack rather than
adding one.

**Second, the browser session.** The hub has never had one. The web role owns the round trip
(redirect, `state` and PKCE verifier in a short-lived signed cookie, callback, code exchange, ID
token verification) and the api role owns the write (identity upsert, session row, `login` audit
row, all in the one transaction `commands.Login` already implements). The session cookie is set
by the web role because the browser is on the web role's origin. Principle II is untouched:
the web role gains a client secret, not a datastore credential. The hard-coded
`Krzysztof W. · Platform · Admin` chip becomes the resolved viewer, and every screen learns to
render a signed-out state instead of asserting an identity nobody has.

**Third, the seven placeholder screens** — and the two unbuilt things underneath them that make
"no mocks" possible at all. `agent-manager seed` is a stub that prints a notice and exits 0, so
every screen's first impression is empty. No scanner worker is registered, so nothing in a
running stack ever writes a scan, a check or a finding, and anything a person imports sits at
"Scanning" for ever. Both are inherited from 001 and both are sequenced here, because a status
badge no process can advance is a placeholder with better typography.

The compose split rides along with the first item: it rewrites the same file, and research R4
confirmed Compose's `include:` keeps `docker compose up` a single command with no flags and no
`.env`.

## Technical Context

**Language/Version**: Go 1.26.5 — unchanged.

**Primary Dependencies**: no new Go module. Everything this feature needs is already required:
`coreos/go-oidc/v3` and `golang.org/x/oauth2` for the authorization-code flow (currently used
for verification only), `a-h/templ` and `starfederation/datastar-go` for the screens,
`danielgtaylor/huma/v2` for the new operations, `oapi-codegen/v2` to regenerate the client.
Two new *infrastructure images*: `ghcr.io/dexidp/dex:v2.44.0` and `glauth/glauth:v2.4.0`.
One image leaves: `quay.io/keycloak/keycloak:26.5`.

**Storage**: unchanged. No new table, no new column, no migration. The `session`, `identity`,
`group_role_map`, `scan`, `scan_check`, `finding`, `finding_evidence`, `override`,
`org_policy`, `audit_event`, `profile`, `profile_entry`, `revision`, `membership`,
`sync_target` and `category` tables all exist from 001's T013–T017 and are unused or
write-only. This feature builds paths to them.

**Testing**: `stretchr/testify` for table-driven units; `testcontainers-go` for anything
crossing Postgres, MinIO or the identity provider — including, newly, a container pair for the
sign-in round trip, since research R2's proof is exactly the test this feature owes. Screen
tests keep using `internal/web/fixture` and gain a signed-in and a signed-out variant of every
screen.

**Target Platform**: Linux containers, `linux/amd64` and `linux/arm64`. Both new identity
images publish arm64 and every measurement in research.md was taken on `aarch64`.

**Project Type**: multi-role web service — unchanged. No new role, no new binary, no new image.

**Performance Goals**: unchanged from 001 (catalog p95 < 300 ms, median fetch-to-verdict
< 60 s), plus: identity discovery live within 5 s of container start (FR-103), and the sidebar
badge counts adding no measurable page-render cost (R5).

**Constraints**: the web role holds no datastore credential; `docker compose up` remains the
only setup step; no Node.js in any image; every rendered value computed from stored data.

**Scale/Scope**: ten screens, of which seven change from placeholder to real; one new
credential-sensitive api operation plus the query and command layers behind five screens; two
infrastructure containers swapped for one.

## Constitution Check

*GATE: evaluated before Phase 0 and re-evaluated after Phase 1 design.*

| Principle | Pre-design | Notes |
| --- | --- | --- |
| I. One module, one image, roles as subcommands | PASS | No new module, no new image, no new subcommand. Dex and glauth are third-party infrastructure, which principle VI's final clause explicitly excludes from this principle. |
| II. Least privilege between roles (NON-NEGOTIABLE) | PASS, and it is the design's central constraint | The web role gains an OIDC client secret and gains **no** datastore or object-store credential. That is precisely why the session row is written through the api and not by the role that sets the cookie (research R3). `internal/archcheck` continues to fail the build if anything under `internal/web` imports the store. |
| III. Untrusted input is the default | PASS, with new surface to cover | Three new untrusted inputs: the OIDC callback's `state` and `code`, the deep-link return target, and the device user code typed into a form. Each gets an explicit rule — single-use state, local-path-only return target, and the existing constant-time code comparison. Provider error text and every new screen's package-derived content are escaped by templ; `templ.Raw` remains banned. |
| IV. Immutability and provenance | PASS | Sign-in, sign-out, approve, reject, publish, share and every administration change each write exactly one audit row in the mutation's own transaction. `audit_event` stays append-only by revoked grant. |
| V. Contract-first, generated, never hand-copied | PASS | Every new operation is a typed huma operation emitting OpenAPI 3.1; the web role reaches all of them through the generated client. No request or response type is hand-written twice. |
| VI. It runs with one command | PASS, and better than before | `include:` keeps `docker compose up` a single argument-free command (R4), and the identity provider now answers in ~1 s instead of 9 s. The constitution's own text names Dex as the local substitute, so this restores its letter. |
| VII. Background roles are declarative plugins | PASS | The scanner arrives as one `worker.Definition` added to the single `internal/worker/roles` list, with `Needs{DB: ReadWrite, Blob: AccessRead}` and no blob writer in scope. Its checks go in the check registry the same pattern already defines. |
| VIII. Commands and queries separated in code | PASS | Every screen's read path lands in `internal/api/queries/`, every mutation in `internal/api/commands/`. **No second projection.** R5 records that if the sidebar counts prove slow the answer is to drop a badge, not to add one. |
| IX. The queue is a separate database, enqueue is transactional | PASS | The scanner consumes jobs the fetcher already enqueues through the outbox. Rescan-on-new-version (001 US4 scenario 5) enqueues through the outbox like every other path — never by calling the queue from a handler. Scan handlers are idempotent: a version that already has a scan for the current pack version is a no-op, enforced by `unique (version_id, pack_version)`. |

### Post-design re-check (2026-08-31, after Phase 1)

| Principle | Post-design | Evidence |
| --- | --- | --- |
| I | PASS | One module. Two infrastructure images replace one; no build added. |
| II | PASS, enforced at three layers as before | Types: `config.Web` still has no `DatabaseURL` or `BlobURL` field, so the credential cannot be read even by accident. Grants: `am_api` writes `session`; no web role exists in Postgres to grant. Environment: `compose.yaml`'s web block gains three variables and no others — `AGENT_MANAGER_OIDC_BROWSER_BASE_URL`, `AGENT_MANAGER_SESSION_MINT_SECRET` and `AGENT_MANAGER_WEB_DEV_CREDENTIAL_HINT` — none of which is a datastore or object-store credential. The session-minting operation is the one new place the boundary is load-bearing, and it is protected by a shared secret the web role holds and the api verifies — see the Complexity Tracking table, because this is the feature's one genuine complexity. |
| III | PASS | The three new inputs each have a named rule in `contracts/auth.md`. Provider error text is escaped. The return-target validator is the existing one the theme form already uses. |
| IV | PASS | SC-111 asserts exactly one audit row per new mutating action, extending 001's SC-008 sweep rather than duplicating it. |
| V | PASS | `contracts/openapi-additions.md` declares every new operation. The generated client is regenerated in `task gen:client` and CI's staleness check covers it unchanged. |
| VI | PASS | `quickstart.md` is one command and now includes signing in, which it could not before. Measured start-to-signed-in on the two-file stack is the SC-101 gate. |
| VII | PASS | The scanner is one `Definition` in one list, as `contracts/worker.md` from 001 fixes. |
| VIII | PASS, allowance still unspent | 001's R12 left `catalog_entry` unbuilt because base tables held SC-003. Nothing here spends the allowance. |
| IX | PASS | Scan jobs arrive through the outbox; the handler is idempotent on `(version_id, pack_version)`. |

**One thing this plan proposes that the constitution does not currently say.** The Technology
Constraints table and principle VI both name **Dex** as the local identity substitute. Feature
001's R6 overrode that with Keycloak by measurement and the constitution was never amended, so
the repository has been out of step with its own constitution since. This feature returns to
Dex, which needs no amendment — but the record is worth correcting, and a one-line note in the
amendment record is proposed as a follow-up (constitution PATCH, no principle changed).

## Project Structure

### Documentation (this feature)

```text
specs/003-usable-web-ui/
├── plan.md                       # This file
├── spec.md                       # Feature specification
├── research.md                   # Phase 0 — R1..R6, all settled by measurement
├── data-model.md                 # Phase 1 — no schema change; which existing tables wake up
├── quickstart.md                 # Phase 1 — clone to signed-in, and the sign-in round trip
├── contracts/
│   ├── openapi-additions.md      # Phase 1 — every new operation, with its authorisation
│   ├── auth.md                   # Phase 1 — the sign-in flow, cookie and state rules
│   └── local-identity.md         # Phase 1 — the Dex and glauth configuration contract
├── checklists/
│   └── requirements.md           # Spec quality checklist
└── tasks.md                      # Phase 2 — /speckit-tasks output
```

### Source Code (repository root)

```text
compose.infra.yaml                # NEW — postgres, minio, minio-init, dex, glauth, migrations
compose.yaml                      # REWRITTEN — include: + api, web, fetcher, scanner, seed, queue-ui

deploy/local/
├── dex/config.yaml               # NEW — issuer, static client, LDAP connector (R1's matcher)
├── glauth/glauth.cfg             # NEW — two users, two groups, one service account
├── keycloak/realm.json           # DELETED
├── minio/policies.sh             # unchanged
└── postgres-init.sql             # unchanged

internal/config/                  # + OIDC browser base URL; + the dev credential-hint flag
internal/auth/
├── oidc.go                       # authorization-code flow helpers; InsecureIssuerURLContext
│                                 #   no longer needed on the local path
└── session.go                    # unchanged — already resolves sessions and roles

internal/api/
├── operations.go                 # + session mint, viewer, badges, scanner, audit, storage,
│                                 #   profile write, org, device approve
├── commands/                     # + session.go, findings.go, profiles.go, org.go, device.go
└── queries/                      # + viewer.go, badges.go, findings.go, audit.go, storage.go,
                                  #   profile_detail.go, org.go

internal/web/
├── web.go                        # placeholders list DELETED; real routes registered
├── auth.go                       # NEW — /auth/login, /auth/callback, /auth/logout, guard
├── session.go                    # + cookie issuance and clearing (currently read-only)
├── view/                         # + one view model per new screen
├── components/
│   ├── shell.templ               # the hard-coded viewer chip becomes the resolved viewer
│   ├── signin.templ              # NEW
│   ├── profiles.templ            # NEW
│   ├── scanner.templ             # NEW
│   ├── audit.templ               # NEW
│   ├── storage.templ             # NEW
│   ├── org.templ                 # NEW
│   ├── cli.templ                 # NEW
│   └── props.go                  # the hard-coded nav badge counts become computed values
├── hub/                          # + the new operations on the generated client
└── fixture/                      # + signed-in and signed-out fixtures per screen

internal/worker/
├── roles/register.go             # the commented-out scanner entry is uncommented
└── scanner/                      # NEW — Definition, handler, check registry (inherited 001 US4)

internal/cli/run.go               # runSeed stops being notYet (inherited 001 T107)
```

**Structure Decision**: no new top-level directory and no new module. The feature is additive
inside the four packages that already own these concerns — `internal/web` for screens,
`internal/api/{commands,queries}` for the data behind them, `internal/auth` for the flow,
`deploy/local` for the local stack — plus the one genuinely new package,
`internal/worker/scanner`, which 001 already reserved a registry slot and a
`contracts/worker.md` shape for.

## Phase 0 — Research

Complete. See [research.md](./research.md). Six items, all settled by running containers on
2026-08-31:

| Item | Outcome |
| --- | --- |
| R1 | Dex alone still emits no `groups` for a static user (001's R6 confirmed). Dex + glauth does, per user, measured. 268 MB / 1 s vs 730 MB / 9 s. Two non-obvious glauth attribute names recorded so they cost nothing twice. |
| R2 | Dex ignores request `Host`, so the current issuer/discovery split cannot carry over. Inverted: container-reachable issuer plus one browser-facing base URL. Full round trip proven, `InsecureIssuerURLContext` becomes unnecessary. |
| R3 | Web role owns the round trip and the cookie; api role owns the write. One new operation, and it is the feature's sharpest security edge. |
| R4 | Compose `include:` keeps `docker compose up` one argument-free command. YAML anchors do not cross the include boundary — they all move to `compose.yaml`. |
| R5 | Sidebar badges are three indexed counts in one operation. No second projection; if too slow, drop a badge. |
| R6 | "No mocks" also requires the seed (a stub) and the scanner (unregistered). Both are inherited scope, both sequenced. |

**No NEEDS CLARIFICATION remains.**

## Phase 1 — Design

Complete. Four artifacts:

- **[data-model.md](./data-model.md)** — the short version is *no schema change*. Its job is to
  name which of 001's already-migrated tables stop being write-only, what each new query reads,
  and the two state machines this feature drives that were previously unreachable: a finding's
  `open → accepted/rejected` transition, and a device authorisation's
  `pending → approved → consumed`.
- **[contracts/openapi-additions.md](./contracts/openapi-additions.md)** — every new operation
  with its method, path, authorisation and the role it serves. The session-minting operation is
  called out separately because its caller is a role, not a person.
- **[contracts/auth.md](./contracts/auth.md)** — the sign-in flow as a sequence, the cookie
  attributes, the `state`/PKCE rules, the return-target validator, what each failure renders,
  and the signed-out contract every screen must satisfy.
- **[contracts/local-identity.md](./contracts/local-identity.md)** — the Dex and glauth
  configuration as a contract, including R1's two attribute-name traps and the exact claim
  assertion the integration test makes.

## Phase 2 — Tasks

Not produced by this command. `/speckit-tasks` generates `tasks.md`.

The dependency order the task breakdown must respect:

```
US1 local identity ──┬─> US2 sign-in ──┬─> US4 governance screens
   (+ US3 compose)   │                 ├─> US5 profile screens
                     │                 ├─> US6 connect-the-CLI
                     │                 └─> US7 administration screens
                     │
 inherited: seed ────┘   (every screen needs data to show)
 inherited: scanner ─────────────────────> US4 (nothing else writes a finding)
```

US2 gates everything, because a screen cannot render a viewer's own data before there is a
viewer. The seed gates every screen's usefulness. The scanner gates US4 alone but US4 is the
highest-value story, so it is not deferrable.

**Gates that can change the plan** — do not defer these:

| Task | If it fails |
| --- | --- |
| The Dex + glauth claim assertion (R1's matcher) | The group search is misconfigured. Fix the attribute names before writing any screen — every role-gated element depends on the claim. |
| The sign-in round-trip integration test (R2's proof) | The browser/container URL split is wrong. Stop; nothing downstream is testable through the product. |
| `internal/archcheck` after the web role's auth package lands | The web role has acquired a forbidden import. Principle II violation — revert, do not annotate. |
| The audit-row-count sweep (SC-111) | A mutation is writing zero or two rows. Fix before adding the next screen, or the defect multiplies across seven of them. |

## Complexity Tracking

One violation-shaped decision, recorded rather than waved through.

| Violation | Why Needed | Simpler Alternative Rejected Because |
| --- | --- | --- |
| **An api operation whose caller is a role, not a person** — the session mint. Every other operation authorises a bearer session; this one *creates* sessions, so it cannot. It is protected by a shared secret the web role holds and the api verifies, which is a second authentication mechanism in a codebase that deliberately had one. | The web role must set the cookie (it owns the browser's origin) and must not write the session row (principle II). Something has to cross that gap, and whatever crosses it can mint a session for any subject — so it is the most privileged call in the system and is treated as such: constant-time comparison, no logging of the secret, present in both roles' environments and nowhere else, and refused entirely when unset rather than defaulting open. | **Giving the web role a database credential for the `session` table alone** — this is the exact change principle II names as requiring a constitutional amendment, and "just one table" is how the boundary rots. **Having the api own the callback and set the cookie** — the cookie would land on the api's origin and the browser on `:8080` would never send it. **Trusting the container network** — an unauthenticated session-minting endpoint is an account-takeover primitive the moment the api is reachable by anything else, and "it's only on the internal network" is not a control. **Passing the raw ID token to the api and having it re-verify** — better, and worth reconsidering in implementation: it moves verification to the role that owns identity and makes the shared secret a defence-in-depth measure rather than the only control. Recorded here as the preferred refinement if it survives contact with the code. |

Nothing else in this feature adds a pattern, a dependency, a module, an image this project
builds, or a projection. Two infrastructure images replace one, which principle VI's final
clause explicitly does not count.

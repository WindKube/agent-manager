---

description: "Task list for 003-usable-web-ui"
---

# Tasks: A lightweight local identity provider and a web UI with no placeholder screens

**Input**: Design documents from `/specs/003-usable-web-ui/`

**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md),
[data-model.md](./data-model.md), [contracts/](./contracts/)

**Tests**: included. The constitution requires them ("tests before merge, at the layer that can
actually fail"), and four of this feature's success criteria — SC-102, SC-106, SC-107, SC-111 —
are assertions rather than inspections, so they exist only as tests.

**Organization**: grouped by user story. Each phase is a stopping point with a coherent system.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel — different files, no dependency on an incomplete task
- **[Story]**: the user story from [spec.md](./spec.md)
- **[001-Txxx]**: inherited scope from feature 001, carrying its original task id

## Phase order deviates from story number, deliberately

The spec numbers its stories by priority. The phases below run **US3 before US1**, because both
rewrite `compose.yaml`: splitting the file while Keycloak is still in it is a mechanical,
reviewable change, and swapping Keycloak for Dex inside the already-split
`compose.infra.yaml` is a second reviewable change. Doing it the other way round means one
commit that both moves and replaces every identity line, which nobody can review.

```
Setup ─> Foundational ─> US3 split ─> US1 Dex ─> US2 sign-in ─┬─> US4 governance
                                                              ├─> US5 profiles
                                                              ├─> US6 connect-the-CLI
                                                              └─> US7 administration
```

---

## Phase 1: Setup

**Purpose**: the configuration surface every later phase reads.

- [x] T001 Add `BrowserBaseURL` to the OIDC config block in `internal/config/config.go`, read from `AGENT_MANAGER_OIDC_BROWSER_BASE_URL`, optional, empty meaning "the issuer is browser-reachable"
- [x] T002 Add `SessionMintSecret` to **both** the api and web config structs in `internal/config/config.go`. It is the one value both roles must hold; the api MUST refuse to mint sessions when it is empty, so it has no default
- [x] T003 [P] Add `DevCredentialHint bool` to the web config struct in `internal/config/config.go`, read from `AGENT_MANAGER_WEB_DEV_CREDENTIAL_HINT`, defaulting false. It MUST NOT be derived from the issuer URL, the host name or the build type — see FR-119
- [x] T004 [P] Extend the config test in `internal/config/config_test.go` to assert the web struct still has no `DatabaseURL` and no `BlobURL` field after this feature's additions (principle II, by absence)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: without the seed, every screen this feature builds renders an empty state, so every
later phase would be untestable through the product.

**⚠️ No screen story can be validated until this phase is complete.**

- [x] T005 [001-T107] Implement `runSeed` in `internal/cli/run.go` — it currently returns `notYet("seed")`, which prints a notice and exits 0, so the compose one-shot "succeeds" while doing nothing
- [x] T006 [001-T107] Write the seed dataset in `internal/seed/` — the design's 10 packages (4 plugins, 6 skills), 4 profiles, 4 findings and the audit rows, with **conformant** manifests per 001's R1 finding and timestamps relative to seed time so "2 days ago" stays true
- [x] T007 Seed the `group_role_map` rows in `internal/seed/` mapping `eng-platform` → catalog admin and `eng-security` → scanner reviewer. **These two group names are shared with the identity-provider fixture in T018** — a mismatch produces a working login with no role, which is the hardest failure in this feature to diagnose. Define them as one exported constant pair and have both sides read it
- [x] T008 [P] Seed the singleton `org_policy` row and the category vocabulary in `internal/seed/`
- [x] T009 [P] Integration test in `internal/seed/seed_integration_test.go` asserting the seed is idempotent (running it twice leaves the same row counts) and that it writes bundle bytes as well as rows — the compose `seed` service holds the writer key precisely because it does both
- [x] T010 Assert in `internal/seed/seed_integration_test.go` that every seeded package appears on the catalog query with the verdict the design specifies (001 SC-004)

**Checkpoint**: a fresh stack comes up with data in it. No screen is built yet, but nothing that
follows will show an empty page for want of rows.

---

## Phase 3: User Story 3 — Two compose files (Priority: P1)

**Goal**: `compose.infra.yaml` startable alone; `compose.yaml` holding the roles this project
builds; `docker compose up` unchanged as one argument-free command.

**Independent Test**: start the infrastructure file alone and assert every service reaches
healthy or completed with no application container present; then start the application file
against it and assert nothing in infrastructure restarted; then assert the single documented
command still brings up everything.

- [x] T011 [US3] Create `compose.infra.yaml` holding `postgres`, `minio`, `minio-init`, `keycloak` (still, at this point), `migrate-schema` and `migrate-queue`, moved verbatim from `compose.yaml` with their volumes, healthchecks and `depends_on` intact (FR-129, FR-130)
- [x] T012 [US3] Rewrite `compose.yaml` as `include: [compose.infra.yaml]` plus `api`, `web`, `fetcher`, `scanner`, `seed` and the `queue-ui` profile (FR-129, FR-131). **Move all six YAML anchors** (`x-observability`, `x-queue-url`, `x-oidc`, `x-blob-read`, `x-blob-write`, `x-app-image`) into this file — anchors do not resolve across an `include:` boundary (research R4), and they are consumed only by application services, so nothing needs duplicating
- [x] T013 [US3] Preserve the credential-boundary comments and each role's environment block exactly as they read today, and re-check that the `web` block still shows no `DATABASE_URL` and no `BLOB_URL` and that only `fetcher` holds a writer key (FR-133, principle II)
- [x] T014 [US3] Give each file a header comment that makes it intelligible read alone (FR-134), and move the `named volumes` block to whichever file declares the services that use it
- [x] T015 [P] [US3] Integration test in `internal/cli/compose_test.go` (or a `Taskfile` check) asserting `docker compose -f compose.infra.yaml config` is valid alone, that `docker compose config --services` from `compose.yaml` lists services from both files, and that no service name is declared twice (FR-130, FR-132, SC-110)
- [x] T016 [US3] Update `Taskfile.yaml` with an `infra:up` target for the infrastructure-only path, and update `specs/001-agent-manager-hub/quickstart.md`'s "what comes up" tree to match the split

**Checkpoint**: the split is in and Keycloak still works. `docker compose up` is unchanged for a
reader. This is a safe place to stop.

---

## Phase 4: User Story 1 — Dex and glauth replace Keycloak (Priority: P1)

**Goal**: the local identity provider costs 268 MB and answers in a second, and still emits a
per-user `groups` claim.

**Independent Test**: start the infrastructure stack alone. Assert discovery answers within five
seconds and advertises the device-code grant; obtain an ID token for each of the two local users
and assert both carry `groups` and that the two differ; sum the identity images and assert under
300 MB.

**Read [contracts/local-identity.md](./contracts/local-identity.md) before starting.** It records
three attribute-name traps that each cost an iteration to find, and one configuration key that is
accepted at boot and silently ignored.

### Tests for User Story 1 (write first)

- [x] T017 [P] [US1] Integration test in `internal/auth/localidp_integration_test.go` using `testcontainers-go` for dex and glauth, asserting in order: discovery within 5 s; `device_authorization_endpoint` and the `device_code` grant present; a `groups` claim present **for each** of the two users; and that the two claims **differ** (FR-101, SC-103, SC-104). The last assertion is the one that matters — a presence-only check passes against a connector that returns one hard-coded group for everybody

### Implementation for User Story 1

- [x] T018 [US1] Write `deploy/local/glauth/glauth.cfg` — two users in two groups plus one service account for Dex's bind, `baseDN=dc=example,dc=dev`, `nameformat=cn`, `groupformat=ou`. The group names MUST be the constants from T007, and the two users' names and mails MUST be `seed.DirectoryUsers` from the same file — the seed asserts that no seeded identity collides with them, which a second, hand-typed spelling of an address quietly defeats
- [x] T019 [US1] Write `deploy/local/dex/config.yaml` — issuer `http://dex:5556/dex` (**container-reachable**, the reverse of the Keycloak arrangement), memory storage, `skipApprovalScreen`, the `agent-manager` confidential client and the `agent-manager-cli` public client, and the LDAP connector. Use `idAttr: uidNumber`, `groupAttr: uniqueMember` with `userAttr: DN`, and `nameAttr: ou` — each of the three obvious alternatives fails in a way that reads like a different problem
- [x] T020 [US1] Replace the `keycloak` service in `compose.infra.yaml` with `dex` and `glauth`. Dex's healthcheck probes its own discovery path; glauth gets `condition: service_started` rather than a healthcheck, so a broken directory surfaces as a failed login rather than a hung boot
- [x] T021 [US1] Delete `deploy/local/keycloak/realm.json` and every Keycloak reference in `compose.infra.yaml`, `compose.yaml` and the anchors
- [x] T022 [US1] Update the `x-oidc` anchor in `compose.yaml`: issuer becomes container-reachable, `AGENT_MANAGER_OIDC_BROWSER_BASE_URL` is added, `AGENT_MANAGER_OIDC_DISCOVERY_URL` is removed, and `groups` is **added to `AGENT_MANAGER_OIDC_SCOPES`** (FR-106) — the Keycloak realm attached the group mapper to the client so the scope could be omitted; Dex requires it
- [x] T023 [US1] Remove the `oidc.InsecureIssuerURLContext` path from the local flow in `internal/auth/oidc.go`. The discovery document is now fetched from the URL its `issuer` names, so go-oidc's ordinary check passes. **Keep** `VerifierConfig.DiscoveryURL` and its branch — that is how a real provider whose issuer and discovery host genuinely differ is supported — (FR-106) and update the comment, which currently explains a Keycloak-specific arrangement that no longer exists
- [x] T024 [P] [US1] Integration test asserting the images total under 300 MB and that both publish `linux/arm64` (FR-103, SC-103). Every measurement in research.md was taken on `aarch64`; this keeps it that way
- [x] T025 [P] [US1] Test asserting `internal/auth` contains no provider-specific branch, constant or hostname quirk (FR-105, FR-107) — the property that made this swap a configuration change rather than a rewrite
- [x] T026 [US1] Update `internal/auth/oidc_test.go`'s claim fixtures, which currently name Keycloak's token shape
- [x] T027 [US1] Rewrite the identity rows of `specs/001-agent-manager-hub/quickstart.md`'s access table, and add a note to `specs/001-agent-manager-hub/research.md` R6 recording that it is **superseded by 003's R1** — with why: R6's finding about static passwords was correct and still reproduces; what it did not test was Dex in front of a directory
- [x] T028 [P] [US1] Propose the constitution PATCH noted in the plan — principle VI and the Technology Constraints table already name Dex, and the amendment record should say that 001 overrode it by measurement and 003 restored it

**Checkpoint**: the stack is 462 MB lighter and eight seconds faster, and the two seeded users
resolve to two different roles. Still no way to sign in through a browser — that is next.

---

## Phase 5: User Story 2 — Sign in, be recognised, sign out (Priority: P1) 🎯

**Goal**: the hard-coded `Krzysztof W. · Platform · Admin` chip becomes a real viewer, and the
"sign in to browse the catalog" message finally has something to click.

**Independent Test**: request a protected route while signed out, follow the sign-in redirect,
authenticate, assert the landing route is the one originally requested, assert the sidebar shows
the authenticated person's real name and mapped role, then sign out and assert the session no
longer resolves server-side.

**Read [contracts/auth.md](./contracts/auth.md) before starting.** It fixes the flow, both
cookies, the state and PKCE rules, and what each of eleven failures renders.

### Tests for User Story 2 (write first)

- [X] T029 [P] [US2] Integration test in `internal/auth/signin_integration_test.go` driving the **full split-host round trip**: browser leg through the browser-facing base, token exchange from the container network, asserting `iss`, `sub`, `email` and `groups` on the resulting token. This promotes research R2's scratch proof to a test the build runs, and it is the gate — if it fails, nothing downstream is testable through the product
- [X] T030 [P] [US2] Table test in `internal/web/auth_test.go` for the return-target validator: a bare path passes; `//evil.example`, `https://evil.example`, a scheme-relative path and an authority all fall back to `/`. Without this, `/auth/login` is an open redirect with a login button
- [X] T031 [P] [US2] Table test in `internal/web/auth_test.go` for state handling: missing cookie, mismatched value, replayed value and an expired cookie each refuse with no session issued and no code exchanged
- [X] T032 [P] [US2] Test in `internal/api/commands/session_test.go` asserting the session mint is **refused when the shared secret is unset** — no default, no development bypass — and that the secret never appears in a log line, an error message or an audit row

### The api half

- [X] T033 [US2] Add `POST /v1/sessions` to `internal/api/operations.go`, authenticated by the shared secret in constant time, wrapping the existing `commands.Login` (FR-111) — which already upserts the identity, inserts the session and writes the `login` audit row in one transaction, and has never been reachable
- [X] T034 [US2] Implement the mint handler in `internal/api/commands/session.go`. Prefer passing the **raw ID token** and verifying it here rather than accepting parsed claims: verification then lives in the role that owns identity, and the shared secret becomes defence in depth rather than the only control. The plan's Complexity Tracking row records this as the preferred shape
- [X] T035 [P] [US2] Add `DELETE /v1/sessions/current` to `internal/api/operations.go`, wrapping the existing `commands.ExpireSession`, and write the sign-out audit row (FR-115)
- [X] T036 [P] [US2] Add `GET /v1/viewer` to `internal/api/operations.go` returning the display name, email, role and **whether the identity maps to any role at all** (FR-117), from what `auth.Sessions.Resolve` already resolved on the request rather than by re-querying
- [X] T037 [US2] Rate-limit the session mint in `internal/api/middleware.go` — a failure here is worth brute-forcing
- [X] T038 [US2] Regenerate the client with `task gen:client` so `internal/apiclient` carries the three new operations, and add them to `internal/web/hub/`

### The web half

- [X] T039 [US2] Create `internal/web/auth.go` with `/auth/login`, `/auth/callback`, `/auth/logout` (POST — a GET sign-out fires from any image tag) and `/auth/signin`, registered in `internal/web/web.go`
- [X] T040 [US2] Implement the `am_oidc` round-trip cookie in `internal/web/auth.go` — signed, 90 s, `Path=/auth/callback`, carrying state, the PKCE S256 verifier and the return target, and **deleted before the code exchange** so a replayed callback finds nothing
- [X] T041 [US2] Implement the authorization redirect, rewriting only the authorization endpoint's host to `BrowserBaseURL`. This is the **one** place that value is read (research R2)
- [X] T042 [US2] Implement the callback: validate state in constant time, exchange the code against the issuer, verify the ID token, call the session mint, set `am_session`, redirect to the return target
- [X] T043 [US2] Extend `internal/web/session.go` to issue and clear the session cookie per [contracts/auth.md](./contracts/auth.md#cookies) — `HttpOnly`, `SameSite=Lax`, `Secure` derived from the configured public base URL's scheme rather than from the request, and `Max-Age` matching the row's `expires_at` (FR-110). It currently only reads one, with a comment saying login is the only thing that may set it — this is that
- [X] T044 [US2] Add the auth guard middleware in `internal/web/auth.go`: every route except `/healthz`, `/static/*` and `/auth/*` requires a resolved session, redirecting to `/auth/signin` with the requested path as the return target (FR-108, SC-105)
- [X] T045 [US2] Write `internal/web/components/signin.templ` — the hub's name, the configured provider's name, one action, no password field and no registration form or link to one (FR-109). Show the local credentials **only** when `DevCredentialHint` is set
- [X] T046 [US2] Add a `Viewer` value to `Shell` in `internal/web/components/props.go` with **no default and no fallback** (FR-116), and make `Shell` constructible in a signed-out state that renders no viewer chip at all — not a placeholder chip, not initials, not "Guest"
- [X] T047 [US2] Replace the hard-coded `KW` / `Krzysztof W.` / `Platform · Admin` block in `internal/web/components/shell.templ` with the resolved viewer (FR-116), and add the sign-out form alongside the theme toggle
- [X] T048 [US2] Render the no-mapped-role state (FR-117) — signed in, told plainly they hold no role and what to ask for, never an empty catalog implying the registry is empty
- [X] T049 [US2] Implement the eleven failure renderings from [contracts/auth.md](./contracts/auth.md#what-each-failure-renders), with provider-supplied error text escaped
- [X] T050 [US2] Update `internal/web/web_test.go`, which currently **asserts** the strings `"Krzysztof W."` and `"Platform · Admin"` are present, and add a signed-in and a signed-out variant to `internal/web/fixture/`
- [X] T051 [P] [US2] Test in `internal/web/contrast_test.go`'s neighbourhood asserting the product contains no literal display name, email, role or avatar outside a fixture (FR-116, SC-106)
- [X] T052 [US2] Run `internal/archcheck` and confirm the new web auth package acquired no forbidden import. A failure here is a principle II violation — revert, do not add an allowlist entry

**Checkpoint**: a person can sign in, see themselves, and sign out. The catalog and package
detail screens work end to end for a real viewer. Seven routes still show placeholders — but the
product is now honest about who the reader is, which is the defect that made it feel fake.

---

## Phase 6: User Story 4 — The governance screens are real (Priority: P1)

**Goal**: a reviewer triages a finding produced by an actual scan of actual bytes, and reads the
decision back in the audit log with their own name against it.

**Independent Test**: register a package containing a known-hostile pattern with **no seeded data
in the database**, wait for the verdict, triage the finding on the Scanner screen, and assert the
audit log shows exactly one correspondingly-typed row naming the reviewer.

**This phase carries the largest inherited block in the feature.** Nothing in a running stack
writes a scan, a check result or a finding today, so the Scanner screen has nothing real to show
and anything a person imports sits at "Scanning" for ever (research R6).

### The scanner worker — inherited from 001 US4

- [x] T053 [001-T061] [US4] Create `internal/worker/scanner/` with a `worker.Definition` declaring `Needs{DB: AccessReadWrite, Blob: AccessRead}` and **no blob writer** — the type system is what enforces "the scanner never writes bundle bytes" (principle VII)
- [x] T054 [001-T062] [US4] Uncomment the scanner entry in `internal/worker/roles/register.go`, which has been sitting behind a `// T060` comment
- [x] T055 [001-T063] [US4] Implement the scan handler — read the bundle, run the check registry, write `scan`, `scan_check`, `finding` and `finding_evidence` in one transaction. **Idempotent**: a version that already has a scan for the current pack version is a no-op, enforced by `unique (version_id, pack_version)` (principle IX)
- [x] T056 [001-T064] [US4] Implement the check registry in `internal/worker/scanner/checks/` following the same registry pattern `contracts/worker.md` fixes for workers and sources
- [x] T057 [001-T065..T069] [P] [US4] Implement the five checks, one file each, as **data-driven rules loaded from the rulepack** rather than Go control flow — the constitution requires a rule to be addable without a code change or a rebuild
- [x] T058 [001-T070] [US4] Load the rulepack from `AGENT_MANAGER_RULEPACK_DIR`, already wired in the compose scanner block, and ship each rule with a fixture that must trip it and a fixture that must not
- [x] T059 [US4] Remove `profiles: ["workers"]` from the `scanner` service in `compose.yaml` and delete the comment explaining why it was there
- [x] T060 [001-T071] [US4] Implement rescan-on-new-version (001 US4 scenario 5) — enqueued **through the outbox**, never by calling the queue from a handler (principle IX)
- [x] T061 [P] [US4] Integration test in `internal/worker/scanner/scanner_integration_test.go` asserting a hostile fixture reaches a flagged verdict, a benign one reaches clean, and a redelivered job is a no-op

### The api behind the two screens

- [x] T062 [P] [US4] `GET /v1/scanner/summary` in `internal/api/operations.go` + `internal/api/queries/findings.go` — scans in the period, quarantined count, active overrides with nearest expiry, median fetch-to-verdict
- [x] T063 [P] [US4] `GET /v1/findings` (paged, filterable by state and severity) in `internal/api/queries/findings.go`
- [x] T064 [US4] `GET /v1/findings/{id}` returning the finding, its evidence, and **every check that ran** — not only the failing one. A pane showing only failures cannot be told apart from one where nothing else ran (001 US4 scenario 2)
- [x] T065 [US4] `POST /v1/findings/{id}/accept` in `internal/api/commands/findings.go` — writes the finding's new state, the `override` row with its expiry, and one audit row of kind `approve`, in one transaction
- [x] T066 [US4] `POST /v1/findings/{id}/reject` in `internal/api/commands/findings.go` — the version stays quarantined regardless of gate, and cannot be resolved by any profile
- [x] T067 [P] [US4] `GET /v1/audit` (paged, `occurred_at desc`, served by 001 T017's index) in `internal/api/queries/audit.go`
- [x] T068 [US4] `GET /v1/audit/export` — **streamed**, full current scope, not the visible page (001 FR-051). It must not materialise the result set; the audit log is the one table designed to grow without bound
- [x] T069 [P] [US4] `GET /v1/badges` in `internal/api/queries/badges.go` — visible packages, readable profiles, open findings. One operation, three indexed counts, no projection (FR-121, research R5)
- [x] T070 [US4] Regenerate the client and add the operations to `internal/web/hub/`

### The two screens

- [x] T071 [US4] Write `internal/web/components/scanner.templ` and its view model in `internal/web/view/scanner.go` — headline figures, findings list, detail pane with rule, explanation, escaped file-and-line evidence and the full check matrix
- [x] T072 [US4] Wire approve-with-note and reject, with the action **absent or disabled with its reason** when the viewer's role does not permit it (FR-126)
- [x] T073 [US4] Write `internal/web/components/audit.templ` and `internal/web/view/audit.go` — kind badges, actor, source, paging, and the export action
- [x] T074 [US4] Delete the `/scanner` and `/audit` entries from the `placeholders` list in `internal/web/web.go` and register the real handlers (FR-120, FR-123)
- [x] T075 [US4] Replace the hard-coded `Badge: "10"` / `"4"` / `"4"` values in `internal/web/components/props.go` with the computed counts, absent rather than zero when there is nothing to count (FR-121)
- [x] T076 [P] [US4] Integration test asserting the **full loop**: register a hostile package, reach a verdict, approve it, and assert a profile containing it now resolves differently (SC-108). An approval that writes an audit row but changes no resolution is the failure this test exists to catch
- [x] T077 [P] [US4] Extend 001's audit-count sweep to assert exactly one row per action this phase adds (SC-111)

**Checkpoint**: the product's central claim — ingest, scan, adjudicate, account for it — works
through the browser. Five routes still show placeholders.

---

## Phase 7: User Story 5 — The profile screens are real (Priority: P2)

**Goal**: a profile owner curates a set in the browser and publishes a revision the CLI syncs.

**Independent Test**: build a profile from registered packages through the UI alone, toggle a
pin, publish a revision, and assert `amctl sync` writes exactly what the screen displayed.

- [x] T078 [P] [US5] `GET /v1/profiles/{slug}` in `internal/api/queries/profile_detail.go` — entries, resolved versions, each entry's scan state, and **the gate's effect computed by calling the existing resolution logic**, not by restating the gate rules in a query. Two implementations of the gate is how the screen and the CLI start disagreeing
- [x] T079 [P] [US5] `POST /v1/profiles` in `internal/api/commands/profiles.go`
- [x] T080 [US5] `PUT /v1/profiles/{slug}/entries` — float or pin per package, not durable until a revision is published (001 US5 scenario 1)
- [x] T081 [P] [US5] `PUT /v1/profiles/{slug}/sharing` — members and identity-provider groups at the four role levels, forks not inheriting future revisions (001 FR-038)
- [x] T082 [P] [US5] `PUT /v1/profiles/{slug}/targets` — targets affect only what a client writes, never what the server stores (001 US5 scenario 7)
- [x] T083 [US5] `POST /v1/profiles/{slug}/revisions` — a new sequential immutable revision; the previous stays readable; republishing a number is refused, not overwritten (principle IV)
- [x] T084 [US5] Regenerate the client and add the operations to `internal/web/hub/`
- [x] T085 [US5] Write `internal/web/components/profiles.templ` and `internal/web/view/profiles.go` — the list, with each profile's package count, visibility and latest revision, showing exactly the readable set (001 FR-044)
- [x] T086 [US5] Write the profile detail screen — per-entry pin toggle, scan state, the policy note stating what the gate did, sharing, targets, and publish
- [x] T087 [US5] Delete the `/profiles` and `/profiles/:slug` entries from the `placeholders` list in `internal/web/web.go`
- [x] T088 [US5] Wire the profiles sidebar badge to the readable-profile count from T069
- [x] T089 [P] [US5] Integration test asserting each of 001 US5 scenarios 2, 3 and 4 — one per gate mode — changes what resolves, and that the screen's policy note matches
- [ ] T090 [P] [US5] End-to-end test: publish a revision through the UI, run the real CLI's sync, assert what it writes matches what the screen displayed

**Checkpoint**: three routes still show placeholders.

---

## Phase 8: User Story 6 — The Connect-the-CLI screen is real (Priority: P2)

**Goal**: `amctl login` completes in the browser, with no `curl` standing in for a person.

**Independent Test**: run the real CLI's login against the stack, complete approval in the
browser, and assert the CLI receives a token and can sync.

- [x] T091 [P] [US6] `GET /v1/device/authorizations/{user_code}` in `internal/api/queries/device.go` — the requesting host and remaining validity, shown **before** the viewer confirms. The handler MUST NOT log its own path parameter: a user code is bearer-equivalent for the length of its validity
- [x] T092 [001-T090] [US6] `POST /v1/device/authorizations/{user_code}/approve` in `internal/api/commands/device.go` — the `pending → approved` transition in one transaction, single-use, with a `login` audit row naming the host and source `cli / <host>`
- [x] T093 [US6] Make the three refusals distinguishable to the viewer — expired, unknown, already consumed (001 FR-042). Approval by an identity other than the requester is refused and is **not** distinguishable from them: telling an attacker which codes are real is worse than a vague error
- [x] T094 [US6] Regenerate the client and add the operations to `internal/web/hub/`
- [x] T095 [US6] Write `internal/web/components/cli.templ` and `internal/web/view/cli.go` — the code entry form, the host and countdown, the confirm action, and with no pending authorisation the **real** command and hub address read from configuration
- [x] T096 [US6] Delete the `/cli` entry from the `placeholders` list in `internal/web/web.go`
- [x] T097 [P] [US6] Integration test driving the real CLI's login against the stack with approval through the web handler, asserting the CLI receives a token and syncs (SC-109)
- [x] T098 [P] [US6] Refusal tests for all four cases in T093, asserting the wrong-identity case is not distinguishable from the other three

**Checkpoint**: two routes still show placeholders.

---

## Phase 9: User Story 7 — The administration screens are real (Priority: P3)

**Goal**: the last two placeholders go, and each policy toggle changes downstream behaviour
rather than only its own row.

**Independent Test**: change each policy and each mapping through the UI and assert the
downstream behaviour changes; compare the Storage screen's figures against the object store's
own reported state.

- [x] T099 [P] [US7] `GET /v1/organization` in `internal/api/queries/org.go` — provider settings, policy, mappings, categories with counts. It **never returns the client secret**, not even masked in a way that leaks its length
- [x] T100 [P] [US7] `POST /v1/organization/identity/test` — the connection test of 001 US7 scenario 1
- [x] T101 [US7] `POST /v1/organization/identity/secret` — rotate without revealing the current value, returning the new one once
- [x] T102 [US7] `PUT /v1/organization/policy` in `internal/api/commands/org.go`
- [x] T103 [001-T100] [US7] **Wire each policy toggle to real downstream behaviour**: the gate change affects the next resolution; signed-bundles refuses a version with no signature reference **and states it is unverified** (001 FR-048a); community-needs-review routes to a queue; the rescan toggle changes the periodic job. A test asserting only the stored row passes while the feature does nothing
- [x] T104 [P] [US7] Group-to-role mapping CRUD at `/v1/organization/mappings`
- [x] T105 [P] [US7] Category CRUD with counts at `/v1/organization/categories`. **No tag endpoint** — tags are manifest-derived and never admin-editable (001 US7 scenario 5), and an endpoint that could edit them would be the bug
- [x] T106 [P] [US7] `GET /v1/storage` in `internal/api/queries/storage.go` — object count, compressed size, region, CLI read-cache hit rate, key layout for `skills/` and `profiles/`, bucket settings via `bucket.As(&s3Client)`, and recent fetches with outcomes. A figure the bucket declines to report renders as unknown, **never as a default**
- [x] T107 [US7] Regenerate the client and add the operations to `internal/web/hub/`
- [x] T108 [US7] Write `internal/web/components/org.templ` and `internal/web/view/org.go`
- [x] T109 [US7] Write `internal/web/components/storage.templ` and `internal/web/view/storage.go`
- [x] T110 [US7] Delete the `/org` and `/storage` entries from `internal/web/web.go` — **and delete the `placeholders` slice, the `screen` type and the `placeholder` handler entirely**, along with `components.Placeholder`. Leaving the machinery in place is how a placeholder comes back
- [x] T111 [P] [US7] Test per 001 T102 that each toggle changes downstream behaviour, not just its own row
- [x] T112 [P] [US7] Test asserting `getOrganization` never emits the client secret in any form

**Checkpoint**: no route reachable from the navigation renders a placeholder. The not-found
screen survives, because a not-found screen is a real screen.

---

## Phase 10: Polish & Cross-Cutting

- [x] T113 **[SC-102]** Automated navigation sweep in `internal/web/nomock_test.go` — walk every navigation entry in both themes and fail on placeholder copy, on a compiled-in identity, and on a badge value that is not computed (FR-120, FR-121, SC-102). This is the criterion; the quickstart table is for the first time, this test is for every time after
- [ ] T114 [P] **[SC-101]** Timed test from a clean checkout to signed-in-with-data through `docker compose up`, asserting under five minutes (FR-125, SC-101)
- [x] T115 [P] **[SC-109]** Contrast audit extended from three screens to ten, both themes (FR-128, 001 SC-009)
- [x] T116 [P] **[FR-127]** Extend 001's escaping assertions to every screen this feature adds, including identity-provider error text, and confirm the `templ.Raw` ban still holds under `internal/web`
- [ ] T117 [P] Empty-state pass: every new screen renders an empty state naming what would appear and how to bring it about, distinguishable in copy **and in markup id** from an error and from an authorisation refusal (FR-122). Follow the `am-empty-auth` precedent the catalog already set
- [ ] T118 [P] Role-gating pass: every action a role does not permit is absent or disabled with its reason across all seven screens (FR-126)
- [ ] T119 [P] Update `README.md` — the role/credential table, the two-file compose topology, and the identity provider
- [ ] T120 [P] Write `specs/003-usable-web-ui/quickstart.md`'s validations into the repo's own test suite where they are assertions rather than prose
- [x] T121 Delete `internal/web/fixture`'s design-mock viewer values now that every screen test supplies its own
- [ ] T122 [P] Metrics for the paths this feature adds: sign-in outcomes, session mint failures, scan duration (001 T109's histogram now has data)
- [ ] T123 Run the full `quickstart.md` by hand once, on a clean checkout, on `aarch64`. Every measurement in `research.md` was taken there and the stack should be proven there rather than assumed onto it
- [ ] T124 Re-run `internal/archcheck` and the credential-boundary boot test (001 T035 / SC-006) — a feature that adds a login is exactly the feature likely to hand the web role a datastore credential by accident (FR-111, SC-110)
- [ ] T125 Update the constitution's amendment record with the Dex note from T028

---

## Dependencies & Execution Order

### Phase dependencies

- **Phase 1 Setup** — no dependencies
- **Phase 2 Foundational** — depends on Phase 1. **Blocks every screen story**: without the seed, no screen has anything to show
- **Phase 3 US3** — depends on Phase 1. Independent of the seed; can run alongside Phase 2
- **Phase 4 US1** — depends on Phase 3 (it edits `compose.infra.yaml`, which Phase 3 creates) and on T007's group-name constants
- **Phase 5 US2** — depends on Phase 4. A sign-in flow needs a provider that emits the claim
- **Phases 6–9** — all depend on Phase 5. A screen cannot render a viewer's own data before there is a viewer
- **Phase 10 Polish** — depends on whichever stories shipped

### Story dependencies

- **US3** (compose split) — genuinely independent. Could ship alone
- **US1** (Dex) — needs US3 only so the diff is reviewable
- **US2** (sign-in) — needs US1
- **US4, US5, US6, US7** — each needs US2, and none needs another. Four people could take one each
- **US4** additionally needs the inherited scanner block (T053–T061), which nothing else needs

### Gates that can change the plan

| Task | If it fails |
| --- | --- |
| T017 — the Dex + glauth claim assertion | The group search is misconfigured. Fix the attribute names before writing any screen; every role-gated element depends on the claim |
| T029 — the split-host round trip | The browser/container URL split is wrong. Stop. Nothing downstream is testable through the product |
| T052 / T124 — `internal/archcheck` | The web role acquired a forbidden import. Principle II violation — revert, do not annotate |
| T077 — the audit-count sweep | A mutation writes zero or two rows. Fix before the next screen, or the defect multiplies across seven of them |

### Parallel opportunities

- **Phase 1**: T003 and T004 together
- **Phase 2**: T008, T009, T010 after T006
- **Phase 3 and Phase 2** run in parallel — different files entirely
- **Phase 4**: T024, T025 alongside the implementation; T017 first
- **Phase 5**: the four tests T029–T032 together, then the api half (T033–T038) and the web half (T039–T051) in parallel by two people, meeting at T038's generated client
- **Phase 6**: the scanner block (T053–T061) and the api block (T062–T070) are independent until T071 needs both
- **Phases 6–9**: four independent tracks once Phase 5 lands
- **Phase 10**: T113–T122 are almost all [P]

---

## Implementation Strategy

### MVP — stop after Phase 5

Setup → Foundational → US3 → US1 → US2. That delivers: a stack 462 MB lighter that boots eight
seconds faster, a seeded database, and a product where a person signs in, sees themselves, and
browses a real catalog. Seven routes still say "not built yet" — but the two defects that made
the UI feel like a mock, the phantom admin identity and the unfollowable sign-in instruction,
are gone.

### Then, in value order

1. **US4** — the scanner and audit screens. The product's central claim, and the largest phase.
   After this, "e2e usable with no mocks" is substantially true
2. **US5** — profiles. Closes the loop with the CLI that already exists
3. **US6** — connect-the-CLI. Small, and makes the documented onboarding path real
4. **US7** — administration. Last, and the phase that deletes the placeholder machinery itself

### A note on the honest size of this

Phases 6 through 9 are the remainder of feature 001's product surface — roughly 35 of its tasks,
carried here because the specification's no-placeholder guarantee cannot be met without them.
The priority ordering exists precisely so that this can be stopped at any checkpoint with a
coherent system in hand. Scaling it down is a reasonable call; doing it silently is not, which
is why the inherited tasks carry their original 001 ids.

## Notes

- `[P]` means different files and no dependency on an incomplete task
- `[001-Txxx]` marks inherited scope with its original task id, so nothing is silently absorbed
- No task in this feature should require a database migration. One that proposes a schema change
  is a design error until it argues otherwise in review — see [data-model.md](./data-model.md)
- Commit at each checkpoint; every checkpoint is a system that works

---

## Traceability

Every functional requirement FR-101…FR-134 and every success criterion SC-101…SC-111 is claimed
by at least one task above. Feature 001's spec closes with the same table; a requirement nothing
implements is how a spec quietly becomes fiction.

| Requirement | Claimed by |
| --- | --- |
| FR-101 groups claim, per user | T017, T018, T019 |
| FR-102 device endpoint + grant | T017, T019 |
| FR-103 under 300 MB, 5 s | T020, T024 |
| FR-104 no manual import | T018, T019, T020 |
| FR-105 no provider-specific branch | T023, T025 |
| FR-106 browser vs container endpoints | T019, T022, T023 |
| FR-107 unchanged demands on a real provider | T025 |
| FR-108 sign-in reachable from any route | T039, T044 |
| FR-109 no local accounts, JIT provisioning | T033, T045 |
| FR-110 cookie attributes | T040, T043 |
| FR-111 session row written by the api | T033, T034, T052, T124 |
| FR-112 single-use state | T031, T040, T042 |
| FR-113 return to the requested route | T030, T042 |
| FR-114 server-side sign-out | T035, T043 |
| FR-115 one audit row per sign-in/out | T033, T035, T077 |
| FR-116 viewer from the session only | T046, T047, T051 |
| FR-117 no mapped role, stated plainly | T036, T048 |
| FR-118 role resolved per request | T036 (by construction — `auth.Sessions.Resolve`) |
| FR-119 credential hint behind an explicit flag | T003, T045 |
| FR-120 no placeholder on any nav route | T074, T087, T096, T110, T113 |
| FR-121 every count computed | T069, T075, T088, T113 |
| FR-122 empty states distinguishable | T117 |
| FR-123 screens satisfy 001's FRs | T071, T073, T085, T086, T095, T108, T109 |
| FR-124 terminal verdict reachable | T053–T061, T076 |
| FR-125 fresh stack populated | T005–T010, T114 |
| FR-126 impermissible actions absent | T072, T118 |
| FR-127 escaping on every new screen | T049, T071, T116 |
| FR-128 both themes, contrast | T115 |
| FR-129 two compose files | T011, T012 |
| FR-130 infra startable alone | T011, T015 |
| FR-131 app against running infra | T012, T015 |
| FR-132 one command still works | T015, T114 |
| FR-133 credential boundary legible | T013, T124 |
| FR-134 each file readable alone | T014 |
| SC-101 clone to signed-in under 5 min | T114 |
| SC-102 no placeholder, automated sweep | T113 |
| SC-103 5 s and 300 MB | T017, T024 |
| SC-104 two users, two roles | T007, T017 |
| SC-105 signed-out to requested route | T029, T044 |
| SC-106 no compiled-in identity | T051 |
| SC-107 own import reaches a verdict | T061, T076 |
| SC-108 approval changes resolution | T076 |
| SC-109 CLI through the browser | T097 |
| SC-110 boundary assertable from the files | T015, T124 |
| SC-111 exactly one audit row | T077 |

FR-118 is the one entry discharged by construction rather than by new code: `auth.Sessions.Resolve`
already resolves the role from `group_role_map` on every request, so a mapping change takes effect
without a cache to invalidate. T036 asserts it rather than implements it.

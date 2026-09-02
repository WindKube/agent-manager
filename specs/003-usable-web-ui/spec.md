# Feature Specification: A lightweight local identity provider and a web UI with no placeholder screens

**Feature Branch**: `003-usable-web-ui`

**Created**: 2026-08-31

**Status**: Draft

**Input**: User description: "use Dex instead of Keycloak, dex is more lightweight; many UI views show that this is not implemented yet; there is no login/logout/create account view when entering the site, it shows the mockup view with my 'Krzysztof Wiatrzyk Admin' shown as logged in; split composes into compose.infra.yaml (dex, minio, postgres and so on) and compose.yaml (app). Ensure that specification includes e2e usable Web UI (without any mocks there for the user)."

## Context

Feature 001 built the hub's spine — the api, the credential boundary, ingestion, the
catalog, the package detail screen — and feature 002 built the CLI. What it did not build
is a surface a person can actually use. Today, a reader who runs `docker compose up` and
opens `http://localhost:8080` sees this:

| What they see | Why |
| --- | --- |
| A sidebar chip reading **"Krzysztof W. · Platform · Admin"** | Hard-coded in the layout. It is design-mock text, not an identity. Nobody is signed in. |
| **"Sign in to browse the catalog"** where the catalog should be | Correct — but there is no sign-in link, button or route anywhere in the product. The instruction cannot be followed. |
| **"This screen is not built yet"** on seven of ten routes | `/profiles`, `/profiles/:slug`, `/scanner`, `/cli`, `/org`, `/storage`, `/audit` all render a placeholder inside the real shell. |
| Sidebar badge counts of 10, 4, 4 | Design seed values compiled into the binary. They do not count anything. |
| Nothing at all, even after signing in | `agent-manager seed` prints "not implemented in this layer yet" and exits 0. The database is empty. |
| Anything imported stuck at **Scanning** forever | No scanner worker is registered, so no version ever reaches a verdict. |

The stack that serves this costs a 730 MB identity-provider image and nine seconds of
start-up before its discovery document answers.

This feature closes all of it. The measure of done is behavioural and blunt: **a person
who has never seen this repository can start it, sign in, and reach every route in the
sidebar without meeting a placeholder, a hard-coded name, an empty screen, or a value
that is not computed from stored data.**

### Relationship to feature 001

Feature 001 already specifies *what* the seven screens must contain — its US4 (scanner
triage), US5 (profiles), US6 (machine authorisation), US7 (organisation) and US8 (audit
and storage), and FR-022 through FR-053. This specification does not restate that
behaviour and does not amend it. It adds three things 001 does not cover:

1. The **browser session** — 001 assumes an authenticated viewer everywhere and never
   specifies how a person becomes one. Its T090 names "browser approval flow" for the
   device grant only.
2. The **no-placeholder guarantee** — 001 permits a screen to land in a later layer. That
   permission is now spent.
3. The **local stack's shape and cost** — which identity provider, and how the compose
   topology is divided.

Where a screen's content is concerned, 001's requirements are the source of truth and are
referenced by number rather than duplicated.

### Terminology

- **Local stack** — everything `docker compose up` starts on a laptop, with no cloud
  account and no credential the reader has to obtain (001 FR-056, SC-001).
- **Local directory** — the two-user, two-group user store the local identity provider
  authenticates against. It replaces the imported realm.
- **Viewer** — the signed-in person whose identity and role the current page reflects.
- **Placeholder** — any rendered output that states, or implies, that a screen is
  unfinished; any value compiled into the binary that presents itself as data; any name or
  role not read from the viewer's own session.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 — A local identity provider that is cheap and still proves the role mapping (Priority: P1)

An engineer clones the repository on a laptop and starts the stack. The identity provider
is answering in about a second instead of nine, and its images cost a third of what they
did. They sign in as one seeded user and hold one role; they sign in as the other and hold
a different one — because the provider still emits a per-user `groups` claim, which is the
input the hub's group-to-role mapping reads.

**Why this priority**: Every other story in this feature needs somewhere to sign in, and
doing the sign-in work against a provider that is about to be replaced means doing it
twice. The provider swap therefore goes first.

**Independent Test**: Start only the infrastructure stack. Assert the discovery document
answers within five seconds and advertises the device-code grant. Obtain an ID token for
each of the two local users and assert both carry a `groups` claim and that the two claims
differ. Sum the identity images' on-disk size and assert it is under 300 MB.

**Acceptance Scenarios**:

1. **Given** a clean checkout, **When** the infrastructure stack is started, **Then** the
   identity provider's OpenID discovery document is served within five seconds of the
   container starting, and advertises both a device authorisation endpoint and the
   `urn:ietf:params:oauth:grant-type:device_code` grant.
2. **Given** the local directory's two users, **When** an ID token is obtained for each,
   **Then** both tokens carry a `groups` claim, and the two claims differ — one names the
   platform group, the other the security group.
3. **Given** the hub's group-to-role mapping, **When** each of the two local users signs
   in, **Then** they resolve to different role sets, and this is demonstrable with no
   external account and no manual configuration step.
4. **Given** the local identity images, **When** their combined on-disk size is measured,
   **Then** it is under 300 MB.
5. **Given** the hub's identity code, **When** the provider is swapped, **Then** nothing
   outside configuration and the local directory's fixture changes: the ID-token
   verification path stays provider-agnostic, with no branch, quirk or constant naming a
   specific provider.
6. **Given** a first run with no pre-existing volumes, **When** the stack starts,
   **Then** the local directory's users, groups and client registration are present with
   no manual import, no admin console visit and no second command.

---

### User Story 2 — Sign in, be recognised, sign out (Priority: P1)

A person opens the hub and is asked to sign in — by the hub itself, not by a message
telling them to do something the product offers no way to do. They authenticate with the
organisation's identity provider, land back on the page they wanted, and see their own
name, their own email and the role their groups actually map to in the sidebar. When they
sign out, the session is over on the server, not merely forgotten by the browser.

**Why this priority**: This is the defect that makes the product feel fake. A screen that
asserts "Krzysztof W. · Platform · Admin" to every visitor, over a body that says "sign in
to browse", is worse than an error page: it is confidently wrong about who the reader is.

**Independent Test**: Drive the full round trip against the local provider — request a
protected route while signed out, follow the sign-in redirect, authenticate, assert the
landing route is the one originally requested, assert the sidebar shows the authenticated
person's real name and mapped role, then sign out and assert the session no longer
resolves server-side.

**Acceptance Scenarios**:

1. **Given** a signed-out visitor requesting any route other than the sign-in route and
   the health endpoint, **When** the page renders, **Then** they are taken to a sign-in
   screen, and no part of the page names an identity, a role or an avatar.
2. **Given** the sign-in screen, **When** it renders, **Then** it names the hub, names the
   configured identity provider, and offers exactly one action: authenticate with that
   provider. There is no password field, no registration form and no link to one.
3. **Given** a signed-out visitor who requested a deep route, **When** they complete
   sign-in, **Then** they land on the route they originally requested, not on a generic
   home page.
4. **Given** a completed sign-in, **When** any page renders, **Then** the sidebar shows
   the viewer's own display name, their email and the role their groups map to, every
   value read from the resolved session.
5. **Given** a subject the hub has never seen, **When** they authenticate successfully for
   the first time, **Then** an identity is provisioned for them automatically, an audit row
   of kind `login` is written naming them with source `web`, and at no point are they asked
   to create an account.
6. **Given** a signed-in viewer, **When** they sign out, **Then** the server-side session
   is expired, the cookie is cleared, an audit row records the sign-out, and replaying the
   old cookie is refused.
7. **Given** a sign-in callback whose state value is missing, unrecognised or already
   consumed, **When** it is received, **Then** it is refused, no session is issued, and the
   viewer is returned to the sign-in screen with a plain explanation.
8. **Given** an identity whose groups map to no role, **When** they sign in successfully,
   **Then** they are signed in and told plainly that they hold no role and what to ask for
   — never shown an empty catalog that implies the hub has no packages.
9. **Given** an identity's group membership changing at the provider, **When** their
   session is next resolved, **Then** their role reflects the current mapping rather than
   what was true at sign-in (001 FR-045).
10. **Given** the web role, **When** a session is created, **Then** the session record is
    written by the api role. The web role holds no datastore credential before this feature
    and holds none after it (constitution principle II).

---

### User Story 3 — Two compose files: infrastructure and application (Priority: P1)

An operator wants to restart the api after a code change without cycling Postgres, MinIO
and the identity provider with it. A CLI integration test wants the backing services
without the serving roles. Both read one file to learn what the stack depends on and
another to learn what this project runs.

**Why this priority**: It is a small, mechanical change to the same file User Story 1
rewrites, so doing them together means editing the compose topology once instead of twice.

**Independent Test**: Start the infrastructure file alone and assert every service reaches
a healthy or completed state with no application container present. Then start the
application file and assert it comes up against the already-running infrastructure. Then
assert the single documented command still brings up everything.

**Acceptance Scenarios**:

1. **Given** the split files, **When** the infrastructure file is started alone, **Then**
   the database, the object store and its bucket initialisation, the identity provider and
   the local directory, and both migration one-shots reach healthy or
   completed-successfully, and no application container is started.
2. **Given** a running infrastructure stack, **When** the application file is started,
   **Then** the api, web, fetcher and scanner roles come up against it without restarting
   any infrastructure service.
3. **Given** the split files, **When** the quickstart's single documented command is run
   from a clean checkout, **Then** the whole system comes up — 001 FR-056 and SC-001 are
   unchanged by the split, including the under-five-minutes budget.
4. **Given** the split, **When** the application file is read, **Then** each role's
   environment block still shows its credential boundary at a glance: the web role has no
   database URL and no object-store URL, only the fetcher role holds an object-store
   credential that can write (constitution principle II).
5. **Given** the split, **When** either file is read alone, **Then** it is intelligible
   alone: neither depends on a comment in the other to explain what it starts.

---

### User Story 4 — The governance screens are real (Priority: P1)

A security reviewer opens the Scanner screen and triages an actual finding produced by an
actual scan of actual bytes, then reads the decision back in the audit log with their own
name against it.

**Why this priority**: The scanner is why this system exists rather than a shared folder,
and the audit log is what makes a decision accountable. These two screens carry the
product's whole claim. They are also the two that cannot be faked convincingly, because
approving a finding has to change what a profile resolves to.

**Independent Test**: Register a package containing a known-hostile pattern, wait for the
verdict, triage the resulting finding on the Scanner screen, and assert the audit log shows
exactly one correspondingly-typed row naming the reviewer — with no seeded data in the
database at all.

**Acceptance Scenarios**:

1. **Given** a signed-in reviewer, **When** the Scanner screen loads, **Then** it presents
   the content 001 FR-028 and its US4 scenarios 1 and 2 require — the period's scan counts,
   the quarantined count, active overrides with the nearest expiry, median fetch-to-verdict
   duration, the findings list, and for a selected finding its severity, rule identifier,
   subject, prose explanation, file-and-line evidence, and every check that ran with its
   result — every value read from stored scan data.
2. **Given** a flagged version, **When** the reviewer approves it with a note or rejects
   it, **Then** the version's distribution state changes as 001 US4 scenarios 3 and 4
   require, and exactly one audit row is written naming the reviewer.
3. **Given** a signed-in viewer, **When** the Audit log screen loads, **Then** it presents
   the content 001 FR-050 requires — actor, event kind, human-readable text, source — with
   paging, and the export of 001 FR-051 covers the full current scope rather than the
   visible page.
4. **Given** a version registered through the UI after the stack started, **When** its
   fetch completes, **Then** it reaches a terminal verdict state visible in the catalog's
   status column. No version registered through the product may remain in the intermediate
   scanning state indefinitely.
5. **Given** the sidebar's scanner badge, **When** any page renders, **Then** its number is
   the current count of open findings, and it is absent rather than zero-padded when there
   are none.

---

### User Story 5 — The profile screens are real (Priority: P2)

A profile owner curates a named set of packages in the browser, sees how the org's scan
gate affects each one, and publishes a numbered revision that a CLI then syncs.

**Why this priority**: Profiles are how the catalog reaches a machine. The CLI (feature
002) already syncs revisions, so the read path exists and the missing half is the curation
surface — which means real value for moderate work.

**Independent Test**: Build a profile from registered packages through the UI alone, toggle
a pin, publish a revision, and assert `amctl sync` writes exactly what the screen displayed.

**Acceptance Scenarios**:

1. **Given** a signed-in viewer, **When** the Profiles screen loads, **Then** it lists
   exactly the profiles their identity may read (001 FR-044), each with its package count,
   visibility and latest revision, all read from stored data.
2. **Given** a profile, **When** its detail screen loads and is edited, **Then** it
   supports the behaviour 001 US5 scenarios 1 through 7 require — per-package float or pin,
   each package's scan state and the gate's effect on it, sharing with members and groups at
   the four role levels, sync-target selection, and publishing an immutable numbered
   revision.
3. **Given** a published revision, **When** the CLI syncs it, **Then** what it writes
   matches what the screen displayed at publication time.
4. **Given** the sidebar's profiles badge, **When** any page renders, **Then** its number
   is the count of profiles the viewer may read.

---

### User Story 6 — The Connect-the-CLI screen is real (Priority: P2)

An engineer on a new laptop runs `amctl login`, reads a code off the terminal, and types it
into a page in the hub that actually completes the pairing.

**Why this priority**: The device endpoints and the CLI both exist and are tested against
each other; the browser half of the flow is the one piece that has never been built, so the
documented onboarding path currently dead-ends on a placeholder.

**Independent Test**: Run the real CLI's login against the stack, complete approval in the
browser, and assert the CLI receives a token and can sync — with no `curl` standing in for
the browser.

**Acceptance Scenarios**:

1. **Given** a pending device authorisation, **When** the engineer opens the Connect-the-CLI
   screen and enters the user code, **Then** the requesting host and the code's remaining
   validity are shown before they confirm, and confirming completes the pairing so the CLI's
   next poll succeeds (001 US6 scenario 2).
2. **Given** an expired, unknown or already-consumed user code, **When** it is submitted,
   **Then** it is refused with a distinct explanation for each case and no token is issued
   (001 FR-042).
3. **Given** a device authorisation requested by one identity, **When** a different
   identity attempts to approve it, **Then** it is refused.
4. **Given** the screen, **When** it renders with no pending authorisation, **Then** it
   presents the real command to run and the real hub address, read from configuration.

---

### User Story 7 — The administration screens are real (Priority: P3)

An admin reads the organisation's identity settings and policy from the screen that claims
to show them, changes a group-to-role mapping and watches it take effect, and an operator
reads the object store's real state.

**Why this priority**: The system ships with working defaults and every other story
functions without these screens. They are last because they are the least load-bearing —
but they are in scope, because a route in the sidebar that shows a placeholder is the defect
this feature exists to remove.

**Independent Test**: Change each policy and each mapping through the UI and assert the
downstream behaviour changes, not merely the stored row. Compare the Storage screen's
reported figures against the object store's own reported state.

**Acceptance Scenarios**:

1. **Given** the Organization screen, **When** it loads and is edited, **Then** it supports
   the behaviour 001 US7 scenarios 1 through 5 require — provider, issuer, client id, scopes
   and device endpoint shown with a connection test and secret rotation that never reveals
   the current value; group-to-role mapping CRUD; the policy toggles wired to real
   downstream behaviour; and category vocabulary curation with counts, tags staying
   manifest-derived.
2. **Given** the Storage screen, **When** it loads, **Then** it reports the figures 001
   FR-053 and US8 scenario 3 require, every one read from the object store or from stored
   data.
3. **Given** any administration change, **When** it is saved, **Then** exactly one audit row
   records it (001 SC-008).

---

### Edge Cases

- **A person signs in and maps to no role.** They are signed in — authentication succeeded
  — and told so plainly, with what to ask for and whom to ask. They are never shown an empty
  catalog, which would misreport an authorisation state as an empty registry.
- **The identity provider is unreachable when a page is requested.** The sign-in screen
  states the provider cannot be reached and does not offer an action that will fail. It must
  not render as "you are signed out".
- **The api is unreachable when a signed-in page is requested.** The screen says the hub's
  api is unavailable. It must not present as an empty result set or as a sign-out.
- **A session expires mid-visit.** The next request returns the viewer to sign-in, preserving
  the route they were on, and does not present the expiry as an error.
- **Two browser tabs, one signs out.** The other tab's next request is refused and returns to
  sign-in.
- **A callback arrives with an authorisation error from the provider** (access denied, invalid
  scope). The reason is shown as the provider gave it, escaped, with no session issued.
- **A screen has genuinely nothing to show** — no profiles yet, no findings, no audit rows on
  a fresh database. It renders an empty state that says what would appear there and how to
  make it appear. An empty state is not a placeholder; a placeholder describes the
  *software's* incompleteness, an empty state describes the *data's*.
- **A viewer lacks the role for an action a screen offers.** The action is absent or plainly
  disabled with the reason, never present-and-failing.
- **A route that does not exist.** Returns not-found inside the real shell, and the shell's
  sidebar is navigable. This is the one existing placeholder that survives, because a
  not-found screen is a real screen.
- **A deep-link return target is supplied by the caller.** Only a local path is accepted, so
  the sign-in redirect cannot be turned into an open redirect.

---

## Requirements *(mandatory)*

### Functional Requirements

**The local identity provider**

- **FR-101**: The local identity provider MUST emit a `groups` claim in the ID token whose
  value differs per user, because that claim is the sole input to the hub's group-to-role
  mapping (001 FR-040). A provider configuration that starts successfully while silently
  omitting the claim MUST NOT be shipped.
- **FR-102**: The local identity provider MUST advertise a device authorisation endpoint and
  the device-code grant in its discovery document.
- **FR-103**: The local identity provider's combined image footprint MUST be under 300 MB and
  its discovery document MUST answer within five seconds of container start.
- **FR-104**: The local directory's users, groups and client registration MUST be present on
  first start with no manual import step, no admin-console visit and no second command.
- **FR-105**: The hub's ID-token verification path MUST remain free of provider-specific
  branches, constants and quirks. Which provider runs locally is a configuration choice.
- **FR-106**: The local stack MUST publish one issuer that every container can reach, and MUST
  make the authorisation endpoint — the one endpoint a browser has to follow — reachable
  through a separately configured browser-facing base URL. The `iss` claim MUST be checked
  against the configured issuer rather than against the URL the discovery document was fetched
  from, and the hub MUST keep supporting a real provider whose discovery document is served
  from a host other than the one its issuer names.

  **Amended 2026-08-31.** This requirement previously asked for a *browser-reachable* issuer
  alongside container-reachable token and key endpoints, which is the arrangement Keycloak's
  backchannel-dynamic hostname mode made possible. Research R2 measured that Dex ignores the
  request `Host` entirely, so a browser-reachable issuer would publish a `token_endpoint` and a
  `jwks_uri` naming a host no container can resolve. The split is therefore **inverted**, not
  dropped, and the clause that carries the security property — the `iss` check against the
  configured issuer rather than against the fetch URL — is unchanged and tested.
- **FR-107**: Replacing the local identity provider MUST NOT change the set of scopes,
  claims or grants the hub requires of a real production provider.

**The browser session**

- **FR-108**: The hub MUST offer a sign-in surface reachable from any route. A screen that
  instructs a viewer to sign in MUST provide the means to do so.
- **FR-109**: The hub MUST NOT offer local account creation or hold a password. Identities
  are provisioned automatically on first successful authentication, and accounts are managed
  in the organisation's identity provider.
- **FR-110**: A successful sign-in MUST establish a session carried by a cookie that is
  inaccessible to script, restricted against cross-site submission, and marked
  secure-only when the hub is served over TLS.
- **FR-111**: The session record MUST be created by the role that owns the relational schema.
  The role that serves the browser MUST NOT gain a datastore or object-store credential in
  this feature (constitution principle II).
- **FR-112**: Sign-in MUST bind the provider round trip to the requesting browser with a
  single-use value, and MUST refuse a callback whose value is missing, unrecognised or
  already consumed.
- **FR-113**: Sign-in MUST return the viewer to the route they originally requested, and MUST
  accept only a local path as that target.
- **FR-114**: Sign-out MUST expire the session server-side, not merely clear the cookie. A
  replayed cookie MUST be refused.
- **FR-115**: Sign-in and sign-out MUST each write exactly one audit row naming the actor and
  the source (001 FR-050).
- **FR-116**: Every screen MUST derive the viewer's displayed name, email and role from the
  resolved session. No identity, role or avatar may be compiled into the product.
- **FR-117**: An authenticated identity that maps to no role MUST be told so explicitly, and
  MUST NOT be shown a screen whose emptiness implies the registry is empty.
- **FR-118**: A viewer's role MUST be resolved from the current group-to-role mapping on each
  request rather than cached at sign-in (001 FR-045).
- **FR-119**: The sign-in screen MUST NOT display credentials unless the process was started
  with an explicit development flag set for that purpose. The flag MUST NOT be inferred from
  the issuer URL, the host name or the build type, because a credential hint that switches
  itself on is one misconfiguration away from doing it in production. On the local stack the
  seeded credentials MUST additionally be documented in the quickstart, so a first-run reader
  needs no credential they have to invent (001 SC-001) even with the flag unset.

**No placeholder surface**

- **FR-120**: Every route reachable from the shell's navigation MUST render its screen's real
  content. No route may render text stating that a screen is unfinished. The not-found screen
  is the sole exception, being a real screen.
- **FR-121**: Every count, badge, total and figure a screen presents MUST be computed from
  stored data or from the object store's own reported state. No such value may be a constant
  in the product.
- **FR-122**: A screen with no data to show MUST render an empty state naming what would
  appear there and how to bring it about, distinguishable in copy from an error and from an
  authorisation refusal.
- **FR-123**: The seven screens' content MUST satisfy the requirements feature 001 already
  states for them: the scanner FR-025 through FR-030, profiles FR-031 through FR-039,
  machine authorisation FR-041 through FR-045, the organisation FR-046 through FR-049, and
  audit and storage FR-050 through FR-053.
- **FR-124**: A version registered through the product MUST reach a terminal verdict state
  visible in the catalog. An intermediate scanning state that no process can advance is a
  placeholder wearing a status badge.
- **FR-125**: A fresh stack MUST come up populated with representative data (001 FR-057), so
  that no screen's first impression is an empty state.
- **FR-126**: An action a viewer's role does not permit MUST be absent or disabled with its
  reason stated. It MUST NOT be offered and then refused.
- **FR-127**: Content rendered from a package manifest, an instruction file, scan evidence or
  an identity-provider error MUST be escaped (001 FR-055). This applies to every screen this
  feature adds.
- **FR-128**: Every screen this feature adds MUST render correctly in both themes with the
  choice persisted per viewer (001 FR-054), and MUST meet the contrast standard of 001
  SC-009.

**The compose topology**

- **FR-129**: The compose topology MUST be split into an infrastructure file — database,
  object store and its initialisation, identity provider, local directory, and the schema and
  queue migration one-shots — and an application file holding the roles this project builds.
- **FR-130**: The infrastructure file MUST be startable alone and MUST reach a healthy or
  completed state with no application container present.
- **FR-131**: The application file MUST start against already-running infrastructure without
  restarting it.
- **FR-132**: The single documented start command MUST continue to bring up the whole system
  from a clean checkout within the budget of 001 SC-001.
- **FR-133**: Each role's environment block MUST continue to make its credential boundary
  legible on the page (constitution principle II): no datastore or object-store credential
  for the web role, object-store write for the fetcher role alone.
- **FR-134**: Each file MUST be intelligible read alone.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-101**: A reader who has never seen the repository goes from clone to signed in and
  looking at populated data in one command and under five minutes, with no cloud account and
  no credential they have to obtain.
- **SC-102**: Every route reachable from the shell's navigation is visited in both themes and
  none renders placeholder text, a hard-coded identity, or a figure that is not computed from
  stored data — verified by an automated sweep that walks the navigation, not by inspection.
- **SC-103**: The identity provider answers its discovery document within five seconds of
  container start, and its images total under 300 MB — against the nine seconds and 730 MB
  measured for the provider being replaced.
- **SC-104**: The two seeded local users sign in and resolve to different role sets, proving
  the group-to-role mapping end to end with no external account.
- **SC-105**: A signed-out visitor to any protected route reaches a sign-in screen, completes
  sign-in against the local provider, and lands on the route they first requested — in under
  30 seconds of human effort and with no step performed outside the browser.
- **SC-106**: No screen displays a name, email, role or avatar that is not read from the
  viewer's own resolved session — verified by asserting the product contains no such literal.
- **SC-107**: A package registered through the UI on a fresh stack reaches a terminal verdict
  and appears with that verdict in the catalog, with no seeded rows involved.
- **SC-108**: Approving or rejecting a finding through the UI changes what a profile resolves
  to, and the change is readable in the audit log naming the reviewer — the whole loop driven
  through the browser.
- **SC-109**: A machine goes from unauthenticated to holding a resolved lockfile using only
  the real CLI and the browser, with no `curl` and no manual database step (001 SC-007,
  now provable through the product).
- **SC-110**: The infrastructure file starts alone to a healthy state, the application file
  then starts against it, and every role's credential boundary is still assertable from the
  files alone (001 SC-006).
- **SC-111**: Every mutating action this feature adds — sign-in, sign-out, approve, reject,
  publish, share, each administration change — produces exactly one audit row (001 SC-008).

---

## Assumptions

- **The identity provider is Dex, with a lightweight LDAP directory behind it.** This
  reverses feature 001's research decision R6, which measured Dex and rejected it. That
  rejection was correct and its cause is unchanged: re-measured on 2026-08-31 against Dex
  v2.44.0, a `groups:` key on a `staticPasswords` entry is accepted at boot without warning
  and **silently ignored**, and the ID token for such a user carries no `groups` claim at all.
  What R6 did not test is Dex in front of a directory that does carry groups. Measured the
  same day: Dex v2.44.0 with an LDAP connector against glauth v2.4.0 returns
  `groups: ['eng-platform']` for one user and `groups: ['eng-security']` for the other, with
  its discovery document live one second after start and a combined image footprint of
  268 MB against Keycloak's 730 MB and nine seconds. The group-search matcher must be keyed
  on the directory's own attribute names, which is the one configuration detail the plan
  phase must get right rather than assume.
- **Two containers replace one.** This is a deliberate trade: the constitution's principle VI
  already holds that third-party infrastructure images are not a second build, and 268 MB
  across two images is cheaper than 730 MB across one. If the plan phase finds a single
  lightweight provider that emits per-user groups from a file-based user store, it is a
  strictly better answer and should be taken.
- **Authentication is federated; the hub never holds a password.** "Create an account" has no
  meaning here, so the sign-in surface offers no form and no link to one. First successful
  authentication provisions the identity. A production deployment points at its own provider
  and the local directory is replaced wholesale.
- **The browser session is a cookie over the hub's own opaque session record**, which already
  exists in the schema and is already resolved on every api request. This feature builds the
  path that creates one; it does not introduce a second session mechanism.
- **The web role continues to hold the OIDC client secret** and to reach data only through the
  api. A client secret is not a datastore credential, so principle II is untouched. The
  session record is written through the api because the web role cannot write it.
- **The two roles are on different origins locally**, so the session cookie must be set by the
  role the browser is talking to. This is why the callback lands on the web role rather than
  the api role.
- **Representative seed data is required, not optional.** Feature 001 FR-057 already requires
  it and its T107 is unbuilt, so `agent-manager seed` currently prints a notice and exits 0.
  Without it every screen's first impression is an empty state, which this feature's whole
  point is to remove.
- **A scanner that produces verdicts is required, not optional.** Feature 001's US4 owns it
  and no scanner worker is registered today, so nothing in a running stack ever writes a scan,
  a check result or a finding. Without it the Scanner screen can only ever display seeded rows
  and anything a person imports themselves sits at "Scanning" forever — a placeholder with a
  status badge instead of a heading.
- **Sidebar badge counts are cheap to compute** at page render through the api, and do not
  need a projection. Should measurement say otherwise, principle VIII's single-projection
  allowance is already spent on the catalog entry, so the answer is to drop a badge rather
  than to add a projection.
- **The design document remains the visual source of truth** for the seven screens. This
  feature changes what data reaches them, not what they look like.

---

## Dependencies

This feature cannot meet SC-101, SC-102, SC-107 or SC-108 while the following work from
feature 001 remains unbuilt. It is inherited scope, not an external blocker, and the plan and
task breakdown must schedule it:

| Inherited from 001 | Why this feature needs it | Blocks |
| --- | --- | --- |
| T107 — `agent-manager seed` | Every screen's first impression is otherwise an empty state | FR-125, SC-101, SC-102 |
| T061–T072 — the scanner worker, rulepack and checks | Nothing writes a scan, a check result or a finding, so the Scanner screen has nothing real to show and imports never leave "Scanning" | US4, FR-124, SC-107, SC-108 |
| T073–T087 — profile curation and revision publishing | The profile read path exists; the write path does not | US5 |
| T098–T102 — organisation settings, mapping CRUD, policy wiring | No endpoint exists behind the Organization screen | US7 |
| T103–T106 — audit read path, export, storage figures | No endpoint exists behind the Audit or Storage screens | US4, US7 |
| T090 — browser device approval | The Connect-the-CLI screen's confirm action | US6 |

The api operations behind five of the seven screens do not exist yet either. They are part of
this feature's work, and the generated-client rule (constitution principle V) means each one
is declared once as a typed operation and reaches the web role through generated code.

**The honest scope note**: the sum of the above is the remainder of feature 001's product
surface. This feature is large, and its priority ordering exists so that it can be stopped
after any story with a coherent system in hand. Stories 1 through 4 are the ones that change
the product from a demonstration into something usable.

---

## Out of Scope

- **Changing what the seven screens look like.** The design document stands; this feature
  makes the data real.
- **New product capability on those screens.** Where feature 001 specified a screen's
  behaviour, that specification is implemented, not extended.
- **A second session mechanism, an API-key surface, or service accounts.** People sign in
  through the provider; machines use the device grant that already exists.
- **Self-service registration, password reset, profile editing of one's own identity, or any
  local credential store.** Identity is the provider's job.
- **Multi-factor authentication and session-management screens** (list my sessions, revoke a
  device). The provider owns the first; the second is a later feature.
- **Provider-side group administration.** The hub reads the `groups` claim; it does not write
  groups back.
- **Signature verification.** Unchanged from 001: modelled and gated, not cryptographically
  verified.
- **A production deployment manifest.** Compose remains the delivery target, now as two files.

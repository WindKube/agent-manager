# Phase 0 — Research: a lightweight local identity provider and a web UI with no placeholder screens

**Feature**: `003-usable-web-ui` · **Date**: 2026-08-31

Every item below was settled by running the thing, not by reading about it. The commands are
reproducible from a clean checkout; the container versions are the ones the plan pins.

---

## R1. Can Dex emit a per-user `groups` claim? — RESOLVED BY MEASUREMENT

**Question**: Feature 001's research R6 measured Dex, found no `groups` claim for a
static-password user, and took its stated fallback of Keycloak. Does that finding still hold,
and if it does, is there a Dex configuration that satisfies FR-101?

**Measured 2026-08-31, Dex v2.44.0, aarch64.**

### R6's finding still holds, exactly as recorded

A `groups:` key added to a `staticPasswords` entry is accepted at boot with no warning and no
log line, and is then **silently ignored**. The ID token for such a user, requested with
`scope=openid email profile groups`, contains:

```
{sub, email, name}          groups: ABSENT
```

Both seeded users, both absent. This is the worst shape a configuration error can take: it
fails at run time as a missing claim rather than at boot as a rejected key. R6 was right and
its rationale is unchanged.

### But R6 did not test Dex in front of a directory

Dex's `local` connector *is* `staticPasswords`, and it has no group field. Dex's LDAP
connector reads groups from wherever it is pointed. Pairing Dex with **glauth** — a
single-binary LDAP server configured from one TOML file — gives per-user groups:

```
kwiatrzyk@example.com  ->  groups: ['eng-platform']
anowak@example.com     ->  groups: ['eng-security']
```

**Decision**: the local identity provider is **Dex v2.44.0 with an LDAP connector against
glauth v2.4.0**.

**Rationale**:

| | Keycloak 26.5 | Dex alone | **Dex + glauth** |
| --- | --- | --- | --- |
| Image footprint | 730 MB | 178 MB | **268 MB** |
| Discovery document live | 9 s | 1 s | **1 s** |
| `groups` claim present | yes | **no** | **yes** |
| `groups` differs per user | yes | n/a | **yes — measured** |
| Device endpoint + `device_code` grant | yes | yes | **yes** |
| `linux/arm64` image | yes | yes | **yes — both** |
| Configuration surface | one 3.2 KB realm JSON | one YAML | one YAML + one TOML |

2.7× smaller and 9× faster to answer, with the claim that FR-101 makes non-negotiable. The
constitution already names Dex as the local substitute — twice, in principle VI and in the
Technology Constraints table — so this returns the implementation to what the constitution
says, and R6's Keycloak choice becomes a superseded measurement rather than a contradiction.

**The one configuration detail that must not be guessed**: the group search has to be keyed on
the attribute names glauth actually returns, and they are not the obvious ones. glauth serves
users at `cn=<user>,ou=<primary-group>,ou=users,<baseDN>` and answers a group search with an
entry that carries **`ou`, not `cn`**, as its name attribute, and **`uniqueMember` holding full
DNs, not `memberUid` holding usernames**. The working matcher is therefore:

```yaml
groupSearch:
  baseDN: dc=example,dc=dev
  userMatchers:
    - userAttr: DN
      groupAttr: uniqueMember
  nameAttr: ou            # NOT cn — glauth's group entries have no cn
```

and the user search needs `idAttr: uidNumber` in glauth's camelCase spelling; the lowercase
`uidnumber` that reads more naturally produces
`missing following required attribute(s): ["uidnumber"]` and a failed login. Both of these
cost an iteration each to find. They are recorded here so the implementation does not pay for
them again.

**Alternatives considered**:

- **Dex alone, accepting no local groups** — rejected. The claim is the sole input to
  `group_role_map`, so every local user would resolve to zero roles, and US7's screen, the
  role-gated actions and 001's quickstart step "log in as anowak and see a different set"
  would all be undemonstrable without a real IdP. That is a worse defect than the one this
  feature is fixing.
- **Dex's `mockCallback` connector** — rejected. It returns one hard-coded identity with
  hard-coded groups, so it cannot show two users resolving differently.
- **Dex's `authproxy` connector** — rejected. Per-user groups work, but only behind a reverse
  proxy injecting trusted headers, which is a third container *and* a password-less login that
  looks nothing like the real path.
- **Keeping Keycloak** — rejected on the user's stated grounds, now quantified: 462 MB and
  eight seconds per start, for a capability Dex + glauth also has.
- **A hand-rolled OIDC stub** — rejected, unchanged from R6: it tests our own bugs instead of
  the protocol.

---

## R2. Dex has no backchannel-dynamic mode. How do a browser and a container share one issuer? — RESOLVED BY MEASUREMENT

**Question**: Keycloak solved the split-host problem with `KC_HOSTNAME_BACKCHANNEL_DYNAMIC`,
which derives token and JWKS URLs from each request's `Host` header while leaving `issuer`
alone. That is why `AGENT_MANAGER_OIDC_DISCOVERY_URL` and `oidc.InsecureIssuerURLContext`
exist in the code today. Dex has no such setting. What replaces it?

**Measured 2026-08-31.** Dex **ignores the request `Host` entirely**. With
`issuer: http://dex:5556/dex`, the discovery document fetched from the host through
`localhost:5556` returns byte-identical absolute URLs to the one fetched from inside the
container network:

```
issuer                  http://dex:5556/dex
authorization_endpoint  http://dex:5556/dex/auth
token_endpoint          http://dex:5556/dex/token
jwks_uri                http://dex:5556/dex/keys
```

So the current approach cannot be carried over: pointing `issuer` at `localhost` would leave
`token_endpoint` and `jwks_uri` naming a host no container can reach.

**Decision — invert the split.** Configure Dex's issuer to the **container-reachable** URL and
override only the one endpoint a browser has to reach:

| Endpoint | Who reaches it | Value |
| --- | --- | --- |
| `issuer`, discovery, token, JWKS | api and web containers | `http://dex:5556/dex` — used as published |
| authorization endpoint | the operator's browser | host rewritten to a new `AGENT_MANAGER_OIDC_BROWSER_BASE_URL` |

**This was verified as a complete round trip**, not reasoned about:

1. `GET /dex/auth` through `localhost:5556` with the hub's client id and redirect URI →
   `302`, and Dex's own redirect chain preserves the request host rather than rewriting it to
   the issuer.
2. Credentials posted to the LDAP connector's login form → `302` to
   `http://localhost:8080/auth/callback?code=…&state=probe-state-123`, with `state` echoed
   unchanged.
3. That code exchanged **from inside the container network** at `http://dex:5556/dex/token` →
   `200` with an ID token whose claims are `iss: http://dex:5556/dex`, the right subject and
   email, and `groups: ['eng-platform']`.

**Two consequences, both improvements**:

- **`oidc.InsecureIssuerURLContext` can be deleted.** The discovery document is now fetched
  from the same URL its `issuer` names, so go-oidc's ordinary check passes. The existing
  `VerifierConfig.DiscoveryURL` field and its "empty means the ordinary case" branch stay —
  they are how a real provider whose issuer differs from its discovery host is supported — but
  the local stack no longer needs them, and the local stack no longer asks go-oidc to skip a
  check.
- **One new configuration value replaces one provider-specific hostname mode.**
  `AGENT_MANAGER_OIDC_BROWSER_BASE_URL` has a meaning any deployment can state — "the base URL
  a browser should use to reach this provider" — and is unset in production, where the issuer
  is publicly reachable. It is read at exactly one place: building the redirect the browser
  follows. FR-105 is satisfied because nothing branches on which provider is configured.

**Alternatives considered**:

- **`extra_hosts` mapping `localhost` inside the app containers** — rejected. Overriding
  `localhost` in a container to mean another host is a trap for every future reader and breaks
  anything else that assumes loopback is loopback.
- **`host.docker.internal` for the backchannel** — rejected. Still a different hostname from
  the browser's, so it does not actually solve the problem, and its availability varies by
  Docker flavour.
- **Documenting an `/etc/hosts` edit so the browser can resolve `dex`** — rejected outright. A
  manual step violates 001 FR-056 and SC-001.
- **Proxying Dex through the web role's own origin** — rejected. It moves the problem rather
  than solving it: containers would then need the browser-facing base URL too, and it puts an
  identity provider's traffic through a role that must stay credential-poor.
- **Overriding token and JWKS URLs instead of the authorization URL** — rejected. Two
  overrides instead of one, and both on the security-critical backchannel rather than on the
  one endpoint whose only job is to be clicked.

---

## R3. Where does the browser session get created, given the web role holds no datastore credential? — RESOLVED BY DESIGN

**Question**: Constitution principle II forbids the web role a database credential, and
`internal/auth.Sessions` deliberately only *reads* sessions — the comment on
`internal/api/commands/login.go` records that creating one is a command that writes an audit
row. So who does the OIDC dance, and who writes the row?

**Decision — the web role owns the browser round trip; the api role owns the write.**

| Step | Role | Why it must be there |
| --- | --- | --- |
| Redirect to the authorization endpoint | web | It is the origin the browser is on. |
| Hold the `state` and PKCE verifier across the round trip | web | The web role has no table to put them in, so they travel in a short-lived signed cookie scoped to the callback path. |
| Receive the callback, exchange the code, verify the ID token | web | The client secret is a client secret, not a datastore credential; principle II is untouched. |
| Create the identity, the session row and the `login` audit row | **api** | It owns the relational schema and mediates every mutation. |
| Set the session cookie | web | The cookie must be on the origin the browser is talking to, and locally that is `:8080`, not the api's `:8082`. |

This needs one new api operation that takes verified claims and returns a session token. It is
the first operation in this project whose caller is a *role* rather than a person, so its
authorisation is not a bearer session — that is the thing it mints. The plan pins how it is
protected below; it is the single most security-sensitive addition in this feature.

**Why not have the api own the whole flow**: the callback would land on the api's origin and
the cookie would be set there, so the browser on `:8080` would never send it. Cross-origin
cookie sharing between two published ports is not something to build a login on.

**Why not give the web role a database credential just for `session`**: it is precisely the
change principle II calls a constitutional amendment rather than an implementation detail, and
the reason the principle exists is that "just one table" is how the boundary rots.

**Alternatives considered**:

- **Store `state` in the api** — rejected. A round trip to the api to start a login, and a
  table for values that live ninety seconds.
- **Store `state` in a signed cookie without PKCE** — rejected. PKCE costs one hash and closes
  code interception on a public redirect URI; there is no reason to skip it.
- **Put the ID token itself in the session cookie** — rejected. It makes sign-out
  unenforceable server-side (FR-114), makes role changes take effect only at token expiry
  (FR-118), and puts claims in a browser.

---

## R4. Does `docker compose up` survive the file split? — RESOLVED BY MEASUREMENT

**Question**: FR-132 requires the single documented command to keep working after the split.
Compose's `-f a -f b` merges files but requires both flags on every invocation, and
`COMPOSE_FILE` in a `.env` is easy to miss.

**Measured 2026-08-31, Docker Compose v5.3.1.** Compose's top-level `include:` key resolves
transitively and needs no flags:

```yaml
# compose.yaml
include:
  - compose.infra.yaml
services:
  api: …
```

`docker compose config --services` lists services from both files. `docker compose up` with no
arguments starts everything.

**Decision**: `compose.yaml` declares `include: [compose.infra.yaml]` and holds the application
roles. `compose.infra.yaml` is startable alone with
`docker compose -f compose.infra.yaml up`, satisfying FR-130 without a profile.

**Consequence for the shared anchors**: the YAML anchors the current file uses
(`x-observability`, `x-queue-url`, `x-oidc`, `x-blob-read`, `x-blob-write`, `x-app-image`) do
**not** cross an `include:` boundary — each file's anchors are resolved within that file. The
anchors are consumed only by application services, so they move wholesale to `compose.yaml`
and nothing needs duplicating. This is worth stating because the alternative — discovering it
as a parse error mid-split — is the likely way to spend an hour.

**Alternatives considered**:

- **`COMPOSE_FILE=compose.yaml:compose.infra.yaml` in a committed `.env`** — rejected. Invisible
  action at a distance, and it breaks the moment someone passes `-f` explicitly.
- **A single file with profiles** — rejected. It does not give US3 what it asks for: restarting
  the app without cycling Postgres.

---

## R5. Sidebar badge counts without a second projection — RESOLVED BY DESIGN

**Question**: FR-121 forbids the compiled-in `10 / 4 / 4`. The badges need a catalog count, a
readable-profile count and an open-finding count on every page render. Does that need a
projection?

**Decision**: one api operation returning the viewer's own counts, called once per full page
render alongside the screen's own query, and not called at all on a datastar fragment update.
Three indexed counts against tables that already carry the indexes 001 T017 created — the
partial index `(version_id) where state='open'` is exactly the open-finding count.

Principle VIII's single-projection allowance is already spent on `catalog_entry` (and R12 left
it unspent only conditionally). A second projection would be a constitutional amendment. If
measurement says the counts are too slow, **the answer is to drop a badge**, not to add a
projection — recorded here so the decision is not relitigated under deadline.

---

## R6. What does "no mock" actually require? — SCOPE FINDING

**Question**: the specification's SC-102 says no route may show a placeholder. Walking the
current code, is anything else standing between that and the truth?

**Found, and it is not only the seven screens**:

| Finding | Evidence in the tree | Consequence |
| --- | --- | --- |
| `agent-manager seed` is a stub | `internal/cli/run.go:27` — `runSeed` returns `notYet("seed")`, which prints a notice and returns nil | Every screen's first impression is an empty state. The compose `seed` one-shot "succeeds" while doing nothing. |
| No scanner worker is registered | `internal/worker/roles/register.go` lists `fetcher.Definition()` only; the scanner entry is commented out with "T060"; `internal/worker/scanner/` does not exist | Nothing ever writes `scan`, `scan_check`, `finding` or `finding_evidence`. Anything imported sits at "Scanning" for ever, and the Scanner screen has nothing real to triage. |
| Five of seven screens have no api behind them | `internal/api/operations.go` registers health, two device operations, four package operations, two profile reads, bundles, sync — and nothing else | The screens cannot be built as presentation-only work; each needs its query and command layer first. |
| The `scanner` compose service is behind a profile | `compose.yaml` comment: "`worker run scanner` exits with unknown worker until T071" | `docker compose up` is green today only because the scanner is not started. |

**Decision**: the seed and the scanner are **inherited scope, not prerequisites to negotiate**.
They are named in the specification's Dependencies table with their 001 task ids and are
sequenced in `tasks.md`. The alternative — building the Scanner screen against seeded rows only
— produces exactly the class of dishonest surface this feature exists to delete: a status badge
reading "Scanning" that no process will ever advance.

---

## Version pins

| Component | Pin | Reason |
| --- | --- | --- |
| Dex | `ghcr.io/dexidp/dex:v2.44.0` | The version measured in R1 and R2. `linux/amd64`, `linux/arm64`, `linux/arm/v7`. |
| glauth | `glauth/glauth:v2.4.0` | The version measured in R1. `linux/amd64`, `linux/arm64`, `linux/arm/v7`. |
| Docker Compose | ≥ 2.20 | `include:` support (R4). Measured on v5.3.1. |

Both identity images publish `linux/arm64`, and every measurement in this document was taken
on `aarch64` — so the local stack is proven on Apple Silicon rather than assumed onto it.

---

## What this feature does *not* need to research

- **The screens' content and layout.** `docs/design/agent-manager.dc.html` and 001's FR-022
  through FR-053 already fix them. This feature changes where the data comes from.
- **Session token generation, hashing and resolution.** `internal/auth` already generates,
  hashes and resolves opaque session tokens, and resolves roles through `group_role_map` in one
  statement. Sign-in creates a row for machinery that already exists.
- **The device flow's server half.** Built and tested in 001; feature 002's CLI drives it. Only
  the browser approval page is missing.
- **Datastar's interaction budget.** 001's R7 gate passed and the catalog's facets are the
  hardest interaction in the design. Nothing in the seven screens exceeds it.

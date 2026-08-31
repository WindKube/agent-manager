# Quickstart — signing in and reaching every screen

**Feature**: `003-usable-web-ui` | **Date**: 2026-08-31

This is the validation guide for feature 003. Feature 001's
[quickstart](../001-agent-manager-hub/quickstart.md) covers the stack as a whole; this covers
what changes, and it is the script SC-101 through SC-111 are measured against.

The bar: **clone to signed in and looking at populated data, in one command, under five
minutes, with no credential you have to obtain** (SC-101). Before this feature the stack came
up and there was no way to sign in, so this document could not exist.

---

## Run it

```bash
cd agent-manager
docker compose up
```

Still one argument-free command. `compose.yaml` names `compose.infra.yaml` through Compose's
top-level `include:`, so the split is invisible here (research R4).

To restart the app without cycling Postgres, MinIO and the identity provider:

```bash
docker compose -f compose.infra.yaml up -d      # infrastructure only, stays up
docker compose up api web fetcher scanner       # the roles, restart at will
```

## What comes up, and what changed

```
compose.infra.yaml
  postgres ──┬─ agent_manager   (app schema + outbox)   ephemeral host port
             └─ river           (queue only)
  minio ─────── bucket: agent-manager-local
  dex ───────── OIDC + device grant          178 MB, discovery live in ~1 s
    └ glauth ── LDAP directory, 2 users in 2 groups    90 MB
  migrate-schema  ──> migrate-queue           (both run to completion)

compose.yaml   (include: compose.infra.yaml)
  api      :8082 -> :8081   REST + OIDC + device flow + outbox relay
  web      :8080            templ + datastar; NO database or object-store credential
  fetcher                   the only role that can write bundle bytes
  scanner                   reads bytes, writes verdicts     <-- no longer behind a profile
  seed                      one-shot, the design's dataset   <-- no longer a stub
  queue-ui :8085            optional, --profile queue-ui
```

Three things are different from 001's stack beyond the file split:

| | Before | After |
| --- | --- | --- |
| Identity | Keycloak, 730 MB, 9 s to a discovery document | Dex + glauth, 268 MB, ~1 s |
| `seed` | printed "not implemented in this layer yet" and exited 0 | loads the design's dataset |
| `scanner` | behind `--profile workers`; `worker run scanner` exited "unknown worker" | starts by default and writes verdicts |

## Where things are

| What | Where | Credentials |
| --- | --- | --- |
| Web UI | http://localhost:8080 | see the two users below |
| API + OpenAPI | http://localhost:8082/v1 · `/v1/openapi.json` | bearer token from the device flow |
| Dex discovery | http://localhost:5556/dex/.well-known/openid-configuration | — |
| MinIO console | http://localhost:9001 | `minioadmin` / `minioadmin` |
| River UI (optional) | http://localhost:8085 | `docker compose --profile queue-ui up` |

| User | Password | Group | Role it maps to |
| --- | --- | --- | --- |
| `kwiatrzyk@example.com` | `password` | `eng-platform` | catalog admin |
| `anowak@example.com` | `password` | `eng-security` | scanner reviewer |

There is **no admin console to visit and no realm to import** — Dex reads one YAML and glauth
one TOML, both committed under `deploy/local/`.

The sign-in screen does **not** print these passwords unless the web role is started with the
explicit development credential-hint flag (FR-119), which compose sets and nothing else does.
The flag is never inferred from the issuer URL or the host name: a credential hint that switches
itself on is one misconfiguration away from doing it in production.

---

## Validation 1 — sign in (SC-105)

```
1. Open http://localhost:8080/scanner  in a fresh private window.
```

**Expect**: the sign-in screen, not the Scanner screen, and **not** a sidebar chip naming
anybody. Before this feature, this URL rendered "this screen is not built yet" underneath a chip
reading "Krzysztof W. · Platform · Admin".

```
2. Click the single sign-in action. Authenticate as kwiatrzyk@example.com / password.
```

**Expect**, in order:

- the browser goes to `localhost:5556/dex/...` — the browser-facing base, not the issuer
- it returns to `http://localhost:8080/auth/callback?code=...&state=...`
- it lands on **`/scanner`** — the route originally requested, not a home page (FR-113)
- the sidebar shows the real display name and email from the ID token, and the role
  `eng-platform` maps to

```
3. Sign out. Then press Back.
```

**Expect**: the sign-in screen. The session is expired server-side, so the cached page's next
request is refused — the cookie being gone is not the mechanism (FR-114).

```
4. Sign in as anowak@example.com. Compare the role in the sidebar.
```

**Expect**: a different role, from a different `groups` claim, through `group_role_map`
(SC-104). This is the assertion feature 001's research R6 concluded Dex could not support; see
[research R1](./research.md) for why it can.

---

## Validation 2 — no placeholder anywhere (SC-102)

Walk every sidebar entry, in both themes:

| Route | Must show | Must not show |
| --- | --- | --- |
| `/catalog` | seeded packages with real verdicts | a hard-coded badge count |
| `/profiles` | the seeded profiles the viewer may read | "not built yet" |
| `/profiles/<slug>` | entries, resolved versions, the gate's effect | — |
| `/scanner` | the four headline figures, the findings list, a detail pane with the full check matrix | — |
| `/audit` | rows with actor, kind, text, source — including your own sign-in from Validation 1 | — |
| `/cli` | the real command and hub address, read from configuration | — |
| `/org` | provider settings, mappings, policy toggles, categories with counts | the client secret, in any form |
| `/storage` | object count, size, region, key layout, bucket settings, recent fetches | a default standing in for a figure the bucket declined to report |

**The automated version is the one that counts.** SC-102 is asserted by a test that walks the
navigation and fails on placeholder copy, on a compiled-in identity, and on a badge value that
is not computed — not by a person following this table. The table is for the first time; the test
is for every time after.

Toggle the theme on each screen. Contrast is asserted by 001's SC-009 audit, now covering ten
screens rather than three.

---

## Validation 3 — a package you registered yourself reaches a verdict (SC-107)

This is the one that could not be faked with seed data.

```
1. Sign in. Catalog -> "Add source". Give a repository URL, a publisher and a category.
2. Watch the status column.
```

**Expect**: `Scanning`, then a terminal verdict — clean or flagged — within 60 seconds at the
median (001 SC-002). Before this feature, no scanner worker was registered, so this column read
`Scanning` for ever and the Scanner screen could only ever display seeded rows (FR-124).

```
3. If it flagged: open /scanner, select the finding, read the evidence, approve it with a note.
4. Open /audit.
```

**Expect**: exactly one new row, kind `approve`, actor **you**, source `web` (SC-111). And the
version's distribution state changed — a profile containing it now resolves differently
(SC-108). An approval that writes an audit row but changes no resolution is the failure this
step exists to catch.

---

## Validation 4 — the CLI, through the browser (SC-109)

Feature 002's CLI already drives the device endpoints; the browser half of the flow was the
placeholder.

```
1. amctl login --hub http://localhost:8082
2. Read the user code it prints.
3. Open http://localhost:8080/cli in a signed-in browser. Type the code.
```

**Expect**: the screen names the **requesting host** and the code's remaining validity *before*
you confirm. Confirm, and the CLI's next poll returns a token.

```
4. amctl sync
```

**Expect**: what the profile screen displayed. No `curl` anywhere in this validation — 001's
SC-007 was previously only demonstrable by hand.

Then check the refusals, which must read differently from each other (001 FR-042):

| Try | Expect |
| --- | --- |
| A code that never existed | "unknown code" |
| A code past its expiry | "expired" |
| A code you already approved | "already used" |
| A code requested by the *other* user | refused, and **not** distinguishable from the above — telling an attacker which codes are real is worse than a vague error |

---

## Validation 5 — the credential boundary still holds (SC-110)

The point of this check is that a feature which adds a login is exactly the feature likely to
hand the web role a database credential by accident.

```bash
docker compose exec web env | grep -Ei 'database|blob|aws|s3'
```

**Expect: nothing.** The web role gained an OIDC client secret and the shared secret for the
session mint, and no datastore credential. If this prints a DSN, principle II is broken —
revert, do not annotate.

```bash
docker compose -f compose.infra.yaml up -d          # infra alone
docker compose -f compose.infra.yaml ps             # all healthy or completed
```

**Expect**: every infrastructure service healthy or completed with no application container
present (FR-130). Then bring the app up separately and confirm nothing in infrastructure
restarted (FR-131).

Read both files. Each must be intelligible alone (FR-134), and each role's environment block
must still show its credential boundary on the page (FR-133).

---

## Configuration that is new or changed

| Variable | Default | Note |
| --- | --- | --- |
| `AGENT_MANAGER_OIDC_ISSUER` | — | **Now container-reachable** (`http://dex:5556/dex`). It was browser-facing under Keycloak. |
| `AGENT_MANAGER_OIDC_BROWSER_BASE_URL` | unset | **New.** The base a browser uses to reach the provider. Unset in production. Read at exactly one place: building the redirect. |
| `AGENT_MANAGER_OIDC_DISCOVERY_URL` | unset | **No longer used locally.** Kept for a real provider whose issuer and discovery host genuinely differ. |
| `AGENT_MANAGER_OIDC_SCOPES` | `openid profile email groups` | **`groups` is now requested.** The Keycloak realm attached the mapper to the client so the scope could be omitted; Dex requires it. |
| `AGENT_MANAGER_SESSION_MINT_SECRET` | — | Shared between web and api. **The api refuses to mint sessions when unset** — no default, no bypass. |
| `AGENT_MANAGER_WEB_DEV_CREDENTIAL_HINT` | `false` | Shows the local passwords on the sign-in screen. Set only by compose. Never inferred. |

### Why `OIDC_ISSUER` reversed direction

Keycloak had `KC_HOSTNAME_BACKCHANNEL_DYNAMIC`, which rewrote token and JWKS URLs from each
request's `Host` while leaving `issuer` alone. That let `issuer` be browser-facing and the
backchannel container-facing, which is why `OIDC_DISCOVERY_URL` and
`oidc.InsecureIssuerURLContext` exist.

Dex has no equivalent — measured: it ignores `Host` completely and always emits its configured
issuer (research R2). So the split inverts. The issuer becomes container-reachable, everything
backchannel uses it as published, and one new value names the browser-facing base for the single
endpoint a browser touches.

**This removes a workaround rather than adding one.** The discovery document is now fetched from
the URL its `issuer` names, so `oidc.InsecureIssuerURLContext` — which asked go-oidc to skip a
check — is no longer on the local path.

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Signed in, but no role, and `/org` shows the mappings correctly | The glauth group names do not match the `group_role_map` rows the seed wrote. This coupling is the most breakable thing in the local stack; the integration test asserts the end state (two users, two different roles) precisely because a typo here produces a working login with no permissions. |
| `groups` absent from the ID token | Either `groups` is missing from `OIDC_SCOPES`, or Dex's `groupSearch` is misconfigured. Check its logs for `groups search returned no groups`, then check the three attribute-name traps in [local-identity.md](./contracts/local-identity.md) — `uidNumber` not `uidnumber`, `uniqueMember` not `memberUid`, `ou` not `cn`. **A `groups:` key on a `staticPasswords` entry is accepted and silently ignored**; it is not the mechanism. |
| `oidc: issuer did not match` in api or web logs | `OIDC_ISSUER` is still the browser-facing URL. Under Dex it must be the container-reachable one. |
| Browser cannot resolve the authorization endpoint | `OIDC_BROWSER_BASE_URL` is unset, so the browser is being sent to the container-reachable issuer. |
| Sign-in ends on the sign-in screen with no explanation | Check the api's logs for a refused session mint. The most likely cause is `SESSION_MINT_SECRET` set in one role's environment and not the other's. |
| Everything imports but stays `Scanning` | The scanner is not running. It is no longer behind a profile, so check its logs — most likely the rulepack directory is not mounted. |
| Every screen is empty but sign-in works | `seed` did not run or exited early. It is a one-shot: `docker compose logs seed`. |

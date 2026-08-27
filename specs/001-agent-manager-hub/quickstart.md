# Quickstart — Agent Manager

**Feature**: `001-agent-manager-hub` | **Date**: 2026-08-27

Target: clone to a running, populated system in **one command, under five minutes, no cloud
account, no credential you have to obtain** (SC-001). If any step here needs a manual fix,
that is a bug in the stack, not in this document.

---

## Run it

```bash
cd agent-manager
docker compose up
```

Then:

| What | Where | Credentials |
| --- | --- | --- |
| Web UI | http://localhost:8080 | `kwiatrzyk@example.com` / `password` (Keycloak realm user, catalog admin) |
| API + OpenAPI | http://localhost:8081/v1 · `/v1/openapi.json` | Bearer token from the device flow below |
| MinIO console | http://localhost:9001 | `minioadmin` / `minioadmin` |
| Keycloak | http://localhost:8083/realms/agent-manager/.well-known/openid-configuration | `admin` / `admin` for the console |
| River UI (optional) | http://localhost:8082 | `docker compose --profile queue-ui up` |

A second realm user, `anowak@example.com` / `password`, is in the `eng-security` group and
therefore a scanner reviewer — use it to exercise the approve/reject path and see the group
→ role mapping do something real.

## What comes up

```
postgres ──┬─ agent_manager   (app schema + outbox)
           └─ river           (queue only — no app tables, by construction)
minio ─────── bucket: agent-manager-local
keycloak ──── OIDC + device grant, two realm users in two groups
   │
   ├─ migrate-schema   arigaio/atlas — atlas migrate apply    (runs to completion)
   └─ migrate-queue    agent-manager migrate queue            (runs to completion)
          │
          ├─ api       :8081   REST + OIDC + device flow + the outbox relay
          ├─ web       :8080   templ + datastar; NO database or object-store credential
          ├─ fetcher           the only role that can write bundle bytes
          └─ scanner           reads bytes, writes verdicts
                 │
                 └─ seed       one-shot: the design's dataset
```

The two migration containers are `depends_on: service_completed_successfully` gates —
nothing serving starts against an unmigrated schema.

## The seeded tour

`seed` loads the design's dataset, so the screens match `docs/design/agent-manager.dc.html`
on first load (SC-004): 10 packages (4 plugins, 6 skills), 4 profiles, 4 open findings,
audit rows. Timestamps are generated relative to seed time so "2 days ago" stays true.

The seeded manifests are **conformant**, not the ones drawn in the mock — see research R1.
Ten `plugin.json` fields, no `components`/`network`/`filesystem`/`signature`. Capabilities
on the detail page are **inferred by the scanner**, and the panel says so.

1. **Catalog** — search `terraform`, filter to `Plugins`, open the Category facet and watch
   the counts change as you narrow. Sort by Uses.
2. **`community/slack-digest@0.5.1`** — flagged. Open it, then jump to Scanner.
3. **Scanner → `SH-NET-002`** — the evidence quotes `scripts/digest.sh:41` and its `curl`
   to `collect.hexley-metrics.io`. That host came out of the shell AST, not a regex.
   Approve it with a note; watch the audit log gain an `approve` row.
4. **Profiles → Platform Engineer** — toggle a skill from `latest` to `pinned`, publish.
   You get `r15`; `r14` is still readable.
5. **Organization** — flip the scan gate to `block`, re-resolve the profile, and see the
   flagged package fall back to its last clean version with the reason stated.

## Device flow by hand

The CLI is out of scope for this feature (spec Out of Scope), but the endpoints it will use
are live. This is the walkthrough behind the "Connect the CLI" screen:

```bash
# 1. Request authorisation. The host is bound to the request and shown to the approver.
curl -s localhost:8081/v1/device/authorize \
  -H 'content-type: application/json' \
  -d '{"client_id":"agent-manager-cli","host":"'"$(hostname)"'"}' | tee /tmp/da.json

# 2. Open verification_uri_complete in a browser, log in as the realm user, approve.

# 3. Poll. Returns authorization_pending until approved, then a short-lived token.
curl -s localhost:8081/v1/device/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d device_code="$(jq -r .device_code /tmp/da.json)" \
  -d client_id=agent-manager-cli | tee /tmp/tok.json

TOKEN=$(jq -r .access_token /tmp/tok.json)

# 4. Only the profiles this identity may read are enumerated.
curl -s localhost:8081/v1/profiles -H "authorization: Bearer $TOKEN" | jq

# 5. The resolved lockfile — note the `skipped` array and its reasons.
curl -s localhost:8081/v1/profiles/example~platform-engineer/revisions/head \
  -H "authorization: Bearer $TOKEN" | jq '.entries, .skipped'
```

Log in as `anowak` instead and step 4 returns a different set. That is FR-044 working, not
a filtered view.

## Development

```bash
task gen              # templ + tailwind + oapi-codegen client
task migrate:diff     # Atlas: diff Bun models -> versioned SQL
task migrate:apply    # apply locally (compose does this for you)
task test             # unit tests (memblob, no containers)
task test:integration # testcontainers: postgres, minio, keycloak
task lint             # golangci-lint + the role-import rule
```

**`task migrate:diff` needs a Docker socket** — Atlas computes the diff against a throwaway
`docker://postgres/16/dev` database. `migrate apply` does not, which is why the init
container is plain. Generating migrations in a locked-down CI runner will fail; applying
them will not.

After editing anything in `internal/store/models`, run `task migrate:diff` and commit both
the generated SQL and the updated `atlas.sum`. CI fails on a stale `atlas.sum`.

## Configuration

Every role reads `AGENT_MANAGER_*` via `caarlos0/env`. What each role is given is the
credential boundary made visible (principle II) — this table is worth reading before
changing `compose.yaml`:

| Variable | api | web | fetcher | scanner |
| --- | :-: | :-: | :-: | :-: |
| `DATABASE_URL` | `am_api` | **absent** | `am_fetcher` | `am_scanner` |
| `RIVER_DATABASE_URL` | ✓ | — | ✓ | ✓ |
| `API_BASE_URL` | — | ✓ | — | — |
| `BLOB_URL` | read | **absent** | **read+write** | read |
| `OIDC_ISSUER` / `_DISCOVERY_URL` / `_CLIENT_ID` / `_CLIENT_SECRET` | ✓ | ✓ | — | — |
| `RULEPACK_DIR` | — | — | — | ✓ |

`web` has no `DATABASE_URL` and no `BLOB_URL`. That is not an oversight to tidy up later —
it is the boundary, and a test boots each role with only its own environment to prove the
role still works and cannot reach past it.

The object-store keys are two, not one: `am-fetcher` can write the bucket and `am-reader`
cannot. `internal/blob` already hands the scanner a `blob.Reader` with no write method, but a
type boundary is only worth the credential behind it — with a single root key, code that
bypassed the interface would still succeed.

### `OIDC_DISCOVERY_URL`, and why it exists

Keycloak's `iss` claim and its authorisation and device endpoints have to be reachable from
the operator's **browser** (`http://localhost:8083`). Its token and JWKS endpoints have to be
reachable from the **api and web containers** (`http://keycloak:8083`). One hostname cannot be
both, so compose sets `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`: Keycloak then derives the
backchannel URLs from the request's Host header and leaves `issuer` alone. Measured, the same
discovery document reads:

| | fetched from the host | fetched from the compose network |
| --- | --- | --- |
| `issuer`, `authorization_endpoint` | `localhost:8083` | `localhost:8083` |
| `token_endpoint`, `jwks_uri` | `localhost:8083` | **`keycloak:8083`** |

go-oidc refuses a document whose `issuer` differs from the URL it was fetched from, which is
exactly this case, so `auth.NewVerifier` passes `oidc.InsecureIssuerURLContext` when the two
URLs differ. That disables one string comparison between two values the operator supplied.
Signature, audience and expiry verification are untouched, and the `iss` claim is still
checked against `AGENT_MANAGER_OIDC_ISSUER`.

Against a real IdP the two URLs are the same, `DISCOVERY_URL` is left unset, and the strict
check runs as normal.

`AGENT_MANAGER_OIDC_SCOPES` is `openid profile email` locally and
`openid profile email groups` by default. The local realm attaches the group-membership
mapper to the client rather than to a requestable scope, because a realm import that declares
`clientScopes` **replaces** Keycloak's built-in set — `profile`, `email`, `roles` and friends
all vanish and every token request fails with `invalid_scope`. A real IdP wants the scope
requested, which is why the code's default includes it.

## Troubleshooting

**Keycloak says "Account is not fully set up"** — one message, three causes, and the real
one appears only in the container log as `error="resolve_required_actions"`: a credential
imported without `"temporary": false`, a user missing `firstName`/`lastName`, or the
`VERIFY_PROFILE` required action left enabled. The shipped realm handles all three.

**`migrate-schema` exits non-zero on first run** — check `atlas.sum` is committed and
matches the migration files. Atlas refuses a directory whose integrity hash does not match,
which is the feature working.

**`atlas migrate diff` wants to drop River's tables** — it is pointed at the wrong database.
Atlas gets `agent_manager` only; River lives in `river` and migrates itself (R11). If you
ever see this, the two URLs have been collapsed onto one database.

**The web UI renders but every page is empty** — `web` cannot reach `api`. It has no
database to fall back on, by design; check `API_BASE_URL` and that `api` is healthy.

**A registration hangs in `Scanning`** — the outbox relay is not draining. It runs inside
`api`; check `api` logs for `outbox_new`. The 10-second sweep means a missed `NOTIFY` costs
seconds, so a permanent stall is the relay being down, not a lost notification.

**A registration from a URL fails immediately with a fetch error** — expected for anything
resolving to a private address. The SSRF client refuses loopback, link-local and RFC1918 on
every redirect hop. To register something local, use the archive upload path.

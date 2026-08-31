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
| Web UI | http://localhost:8080 | `kwiatrzyk@example.com` / `local-only-directory-password` (directory user, catalog admin) |
| API + OpenAPI | http://localhost:8082/v1 · `/v1/openapi.json` | Bearer token from the device flow below |
| MinIO console | http://localhost:9001 | `minioadmin` / `minioadmin` |
| Identity (Dex) | http://localhost:5556/dex/.well-known/openid-configuration | No console. The whole provider is `deploy/local/dex/config.yaml` plus the directory in `deploy/local/glauth/glauth.cfg` |
| River UI (optional) | http://localhost:8085 | `docker compose --profile queue-ui up` |

A second directory user, `anowak@example.com`, same password, is in the `eng-security`
group and therefore a scanner reviewer — use it to exercise the approve/reject path and see
the group → role mapping do something real. Both users live in
`deploy/local/glauth/glauth.cfg`; the group names there are the same exported constants the
seed writes into `group_role_map`, and a test parses both sides so they cannot drift.

## What comes up

Two files, one command. `compose.yaml` names `compose.infra.yaml` through Compose's top-level
`include:`, so `docker compose up` with no arguments and no `-f` still starts everything below.

```
compose.infra.yaml — everything the hub depends on and does not build.
                     Startable alone: docker compose -f compose.infra.yaml up -d

  postgres ──┬─ agent_manager   (app schema + outbox)
             └─ river           (queue only — no app tables, by construction)
  minio ─────── bucket: agent-manager-local
  dex ─────────┬─ OIDC + device grant, on :5556
               └─ glauth  the directory behind it: two users in two groups
     │
     ├─ migrate-schema   arigaio/atlas — atlas migrate apply    (runs to completion)
     └─ migrate-queue    agent-manager migrate queue            (runs to completion)
            │
compose.yaml — the roles this project builds
            │
            ├─ api      :8082 → :8081   REST + OIDC + device flow + the outbox relay
            ├─ web      :8080           templ + datastar; NO database or object-store credential
            ├─ fetcher                  the only role that can write bundle bytes
            ├─ scanner                  reads bytes, writes verdicts
            │     │
            │     └─ seed               one-shot: the design's dataset
            └─ queue-ui :8085           optional, --profile queue-ui
```

The two migration containers are `depends_on: service_completed_successfully` gates —
nothing serving starts against an unmigrated schema. Those gates cross the file boundary:
`include:` merges both files into one project, so `api` waiting on `migrate-queue` needs no
change to keep working.

The split is there so the application can be restarted without cycling Postgres, MinIO and
the identity provider — `task infra:up`, then `docker compose up api web fetcher` as often
as you like.

Two host ports are deliberately not mirrored onto the container's. Postgres publishes an
**ephemeral** one (`docker compose port postgres 5432` reports where it landed) and the api is
on **8082**: 5432 and 8081 are both commonly already bound on a developer's machine, and losing
the whole stack to a port nothing inside it uses is not worth the symmetry.

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
curl -s localhost:8082/v1/device/authorize \
  -H 'content-type: application/json' \
  -d '{"client_id":"agent-manager-cli","host":"'"$(hostname)"'"}' | tee /tmp/da.json

# 2. Open verification_uri_complete in a browser, log in as the realm user, approve.

# 3. Poll. Returns authorization_pending until approved, then a short-lived token.
curl -s localhost:8082/v1/device/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d device_code="$(jq -r .device_code /tmp/da.json)" \
  -d client_id=agent-manager-cli | tee /tmp/tok.json

TOKEN=$(jq -r .access_token /tmp/tok.json)

# 4. Only the profiles this identity may read are enumerated.
curl -s localhost:8082/v1/profiles -H "authorization: Bearer $TOKEN" | jq

# 5. The resolved lockfile — note the `skipped` array and its reasons.
curl -s localhost:8082/v1/profiles/example~platform-engineer/revisions/head \
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
task test:integration # testcontainers: postgres, minio, dex + glauth
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
| `OIDC_ISSUER` / `_BROWSER_BASE_URL` / `_CLIENT_ID` / `_CLIENT_SECRET` | ✓ | ✓ | — | — |
| `RULEPACK_DIR` | — | — | — | ✓ |

`web` has no `DATABASE_URL` and no `BLOB_URL`. That is not an oversight to tidy up later —
it is the boundary, and a test boots each role with only its own environment to prove the
role still works and cannot reach past it.

The object-store keys are two, not one: `am-fetcher` can write the bucket and `am-reader`
cannot. `internal/blob` already hands the scanner a `blob.Reader` with no write method, but a
type boundary is only worth the credential behind it — with a single root key, code that
bypassed the interface would still succeed.

### `OIDC_BROWSER_BASE_URL`, and why it exists

One provider has to be reachable from two places that cannot agree on a hostname: the
operator's **browser**, which only knows `localhost`, and the **api and web containers**,
which only know the compose network. Dex publishes one discovery document and ignores the
request `Host` entirely — fetched through `localhost:5556` it returns byte-identical absolute
URLs to the copy fetched from inside the network:

```
issuer                  http://dex:5556/dex
authorization_endpoint  http://dex:5556/dex/auth
token_endpoint          http://dex:5556/dex/token
jwks_uri                http://dex:5556/dex/keys
```

So the issuer is the **container-reachable** URL, used verbatim for discovery, token and
JWKS, and exactly one endpoint is overridden for the browser:
`AGENT_MANAGER_OIDC_BROWSER_BASE_URL=http://localhost:5556/dex`, read at one place —
building the redirect a person clicks. Nothing on the security-critical backchannel is
overridden, and the code does not know which provider it is talking to.

This is **inverted** from the arrangement 001 shipped, which published a browser-reachable
issuer and derived the backchannel from each request's `Host` header. That is a
provider-specific hostname mode, and the provider that has it is not the one this stack runs
any more (003 research R2). The consequence is a net simplification: the discovery document
is now fetched from the URL its own `issuer` names, so go-oidc's ordinary issuer check
passes and the local stack no longer asks it to skip anything.

`AGENT_MANAGER_OIDC_DISCOVERY_URL` is still read, and is **unset locally**. It is for a real
provider that genuinely serves its metadata from another host: `auth.NewVerifier` then
fetches the document from there and requires it to name `AGENT_MANAGER_OIDC_ISSUER`, which
is a stricter check than the one go-oidc would have run, not a weaker one.

`AGENT_MANAGER_OIDC_SCOPES` is `openid profile email groups`, locally and by default — the
same list, which is the point. 001's local realm attached the group-membership mapper to the
client, so the claim arrived whether or not the scope was requested, and the local stack was
the one deployment that did not have to ask for it. Dex only emits `groups` for a client that
requests the scope, so the local stack now asks for exactly what a real provider is asked
for (FR-107).

## Troubleshooting

**A successful login, and no role anywhere** — the ID token arrived with `groups: []`. This
is the one identity failure that reports nothing: Dex's group search found the user, found
no groups, and issued a perfectly valid token. Almost always the `groupSearch` block in
`deploy/local/dex/config.yaml` has been "corrected" to the textbook POSIX pairing
(`memberUid` against the username); glauth answers with full member DNs in `uniqueMember`.
The other two attribute names in that block, `idAttr: uidNumber` and `nameAttr: ou`, fail
loudly instead — HTTP 500, with the real reason only in `docker compose logs dex`.

**Every login is rejected as a wrong password** — check that
`deploy/local/glauth/glauth.cfg` is mounted at exactly `/app/config/config.cfg`. The image's
start script copies its own example directory in when that path is absent, so the directory
comes up healthy, answers binds, and knows nobody.

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

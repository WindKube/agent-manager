# Contract — the local identity provider

**Feature**: `003-usable-web-ui` · **Date**: 2026-08-31

Dex in front of glauth, replacing Keycloak. Everything here was measured on 2026-08-31 on
`aarch64`; see [research.md R1 and R2](../research.md) for the measurements and the rejected
alternatives.

---

## What the local provider must deliver

These are the contract, not the configuration. A different provider satisfying all six is a
legitimate substitution (FR-105 — nothing in the hub may branch on which provider is running).

| # | Requirement | Asserted by |
| --- | --- | --- |
| 1 | An OpenID discovery document within 5 s of container start | integration test, FR-103 |
| 2 | `device_authorization_endpoint` present and `urn:ietf:params:oauth:grant-type:device_code` in `grant_types_supported` | integration test, FR-102 |
| 3 | A `groups` claim in the ID token **for each of the two local users**, with **different values** | integration test, FR-101 · SC-104 |
| 4 | An authorization-code flow whose browser leg works through a host the operator's browser can resolve, and whose token leg works from inside the container network | integration test, R2 |
| 5 | Users, groups and client registration present on first start with no manual step | `docker compose up` from a clean checkout, FR-104 |
| 6 | Combined **unpacked** image footprint under 300 MB — the size `docker image ls` prints, not `docker image inspect`'s `Size`, which is the compressed content size under the containerd snapshotter | integration test, FR-103 |

---

## Topology

```
   browser  ──── http://localhost:5556/dex/auth ────────────┐
                                                            ▼
   api, web ──── http://dex:5556/dex/{,token,keys} ────>  [ dex ]
                                                            │
                                                    LDAP    ▼
                                                        [ glauth ]  ou=users / ou=groups
```

One issuer value, `http://dex:5556/dex`, used verbatim for discovery, token and JWKS. The
browser reaches only `/auth`, through `AGENT_MANAGER_OIDC_BROWSER_BASE_URL`. Dex ignores the
request `Host` entirely and preserves it in its own relative redirects, which is what makes this
work — measured, not assumed (R2).

**`oidc.InsecureIssuerURLContext` is not needed on this path.** The discovery document is fetched
from the URL its `issuer` names, so go-oidc's ordinary check passes. `VerifierConfig.DiscoveryURL`
stays in the code for a real provider whose issuer and discovery host genuinely differ; the local
stack simply stops using it.

---

## Environment

| Variable | Value on the local stack | Note |
| --- | --- | --- |
| `AGENT_MANAGER_OIDC_ISSUER` | `http://dex:5556/dex` | Container-reachable. The trust anchor; the `iss` claim is checked against it. |
| `AGENT_MANAGER_OIDC_DISCOVERY_URL` | *unset* | No longer needed locally. Kept in config for real providers. |
| `AGENT_MANAGER_OIDC_BROWSER_BASE_URL` | `http://localhost:5556/dex` | **New.** The base a browser uses. Unset in production, where the issuer is publicly reachable. Read at exactly one place. |
| `AGENT_MANAGER_OIDC_CLIENT_ID` | `agent-manager` | |
| `AGENT_MANAGER_OIDC_CLIENT_SECRET` | `local-only-oidc-client-secret` | Held by web and api. Not a datastore credential. |
| `AGENT_MANAGER_OIDC_SCOPES` | `openid profile email groups` | **`groups` is now requested**, unlike the Keycloak stack, which omitted it because that realm attached the mapper to the client. Dex requires the scope. This brings the local stack in line with what the code's default wants. |
| `AGENT_MANAGER_OIDC_REDIRECT_URL` | `http://localhost:8080/auth/callback` | The web role's origin. |

---

## Dex configuration

`deploy/local/dex/config.yaml`. The shape below is the measured-working one.

```yaml
issuer: http://dex:5556/dex
storage:
  type: memory              # a laptop IdP with no state to preserve
web:
  http: 0.0.0.0:5556
oauth2:
  skipApprovalScreen: true  # one fewer click; the consent screen teaches nothing here
staticClients:
  - id: agent-manager
    secret: local-only-oidc-client-secret
    redirectURIs:
      - http://localhost:8080/auth/callback
      - http://127.0.0.1:8080/auth/callback
  - id: agent-manager-cli
    public: true            # the CLI holds no secret
connectors:
  - type: ldap
    id: ldap
    name: LDAP
    config:
      host: glauth:3893
      insecureNoSSL: true   # plaintext LDAP on a private compose network, on a laptop
      bindDN: cn=serviceuser,ou=svcaccts,dc=example,dc=dev
      bindPW: <local-only>
      userSearch:
        baseDN: dc=example,dc=dev
        filter: "(objectClass=posixAccount)"
        username: mail
        idAttr: uidNumber           # camelCase — see the traps below
        emailAttr: mail
        nameAttr: cn
      groupSearch:
        baseDN: dc=example,dc=dev
        userMatchers:
          - userAttr: DN
            groupAttr: uniqueMember  # not memberUid — see the traps below
        nameAttr: ou                 # not cn — see the traps below
```

### The three traps, each of which cost an iteration to find

These are the reason this file exists. Getting any one wrong produces a failure that looks like
something else.

1. **`idAttr: uidNumber`, not `uidnumber`.** glauth's attribute names are camelCase and Dex's
   lookup is case-sensitive. The lowercase spelling reads more naturally and fails with
   `ldap: entry "cn=…" missing following required attribute(s): ["uidnumber"]` — which reads like
   a missing directory field rather than a spelling mistake.
2. **`groupAttr: uniqueMember` with `userAttr: DN`, not `memberUid` with `cn`.** glauth answers a
   group search with full member DNs in `uniqueMember`. The `memberUid`/username pairing is the
   textbook POSIX shape and produces
   `ldap: groups search returned no groups` — a *successful* login with no groups, which is
   exactly the silent-claim-loss failure this whole feature exists to avoid.
3. **`nameAttr: ou`, not `cn`.** glauth's group entries carry `ou` and have no `cn`, so `cn`
   fails with `group entity "ou=eng-platform,…" missing required attribute "cn"` **after** the
   group was found — misleading, because the search worked.

**Never add `groups:` to a Dex `staticPasswords` entry.** It is accepted at boot without a
warning, logged nowhere, and silently ignored. That is what feature 001's R6 measured and what
R1 re-measured on Dex v2.44.0. The LDAP connector is the mechanism; static passwords are not.

---

## glauth configuration

`deploy/local/glauth/glauth.cfg`. Two people plus one service account for Dex's bind.

```toml
[ldap]
  enabled = true
  listen = "0.0.0.0:3893"
[ldaps]
  enabled = false
[backend]
  datastore = "config"
  baseDN = "dc=example,dc=dev"
  nameformat = "cn"
  groupformat = "ou"

# Dex's bind account. Needs search; nothing else.
[[users]]
  name = "serviceuser"
  uidnumber = 5003
  primarygroup = 5502
  passsha256 = "<sha256 of the local-only password>"
    [[users.capabilities]]
    action = "search"
    object = "*"

[[users]]
  name = "kwiatrzyk"
  mail = "kwiatrzyk@example.com"
  uidnumber = 5001
  primarygroup = 5501          # eng-platform
  passsha256 = "<sha256>"

[[users]]
  name = "anowak"
  mail = "anowak@example.com"
  uidnumber = 5002
  primarygroup = 5500          # eng-security
  passsha256 = "<sha256>"

[[groups]]
  name = "eng-platform"
  gidnumber = 5501
[[groups]]
  name = "eng-security"
  gidnumber = 5500
[[groups]]
  name = "svcaccts"
  gidnumber = 5502
```

The two group names must match the `group_role_map` rows the seed writes, or the mapping resolves
to nothing and both users hold no role. That coupling is the single most breakable thing in the
local stack, so the integration test asserts the end state — *these two users resolve to these
two different roles* — rather than asserting the claim alone.

`passsha256` is the hex sha256 of the password. glauth also accepts `passbcrypt`; sha256 is used
here because these are laptop credentials documented in the quickstart, and a slow hash on a
fixture buys nothing.

---

## Health probes

| Service | Probe |
| --- | --- |
| dex | `GET /dex/.well-known/openid-configuration` returning 200. Dex's image has no curl, so the probe is either its own `dex` binary or the shell's `/dev/tcp`, the same technique the Keycloak probe used. |
| glauth | TCP connect to `3893`. Its image is a single static binary with no shell utilities; a bind-and-search probe is not worth a second container. |

`api` and `web` depend on `dex: service_healthy`. Nothing depends on glauth directly — Dex does,
and Dex is not healthy until its own probe passes, which needs no LDAP round trip. So glauth gets
`depends_on` from dex with `condition: service_started`, and a genuinely broken directory surfaces
as a failed login rather than a failed boot. That is the correct trade for a laptop: a stack that
starts and then tells you the directory is wrong beats a stack that hangs on a health check.

---

## The integration test this feature owes

One test, `testcontainers-go`, containers for dex and glauth, asserting in order:

1. Discovery answers within 5 s and advertises the device endpoint and the `device_code` grant.
2. For **each** of the two users: obtain an ID token, assert `groups` is present and non-empty.
3. Assert the two `groups` values **differ**. A test that only checks presence would pass against
   the `mockCallback` connector, which returns one hard-coded group for everybody.
4. Drive the full authorization-code round trip with the browser leg on one host and the token
   exchange on another, asserting `iss`, `sub`, `email` and `groups` on the resulting token. This
   is R2's proof, promoted from a scratch probe to a test the build runs.
5. Assert the two users resolve to two different roles through `group_role_map` — the end
   property SC-104 names, which is the only assertion that catches a group-name typo in the
   glauth fixture.

Steps 3 and 5 are the ones that matter. Everything else in this contract can be right while the
claim is silently empty, and that failure mode is what cost feature 001 its Keycloak detour.

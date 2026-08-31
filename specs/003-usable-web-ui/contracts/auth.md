# Contract — the browser sign-in flow

**Feature**: `003-usable-web-ui` · **Date**: 2026-08-31

This fixes the sign-in flow, the cookie, the round-trip state and the signed-out contract every
screen must satisfy. Research [R2](../research.md) proved the URL split it depends on and
[R3](../research.md) settled which role does which half.

---

## The flow

```
  browser                     web role (:8080)              api role (:8081)        Dex
     │                              │                              │                 │
  1  │ GET /scanner                 │                              │                 │
     │─────────────────────────────>│                              │                 │
     │  302 /auth/login?return=…    │                              │                 │
     │<─────────────────────────────│                              │                 │
     │                              │                              │                 │
  2  │ GET /auth/login              │  mint state + PKCE verifier  │                 │
     │─────────────────────────────>│  Set-Cookie: am_oidc (90s)   │                 │
     │  302 to BROWSER_BASE/auth?…  │                              │                 │
     │<─────────────────────────────│                              │                 │
     │                              │                              │                 │
  3  │ authenticate ────────────────────────────────────────────────────────────────> │
     │  302 /auth/callback?code&state <──────────────────────────────────────────────  │
     │                              │                              │                 │
  4  │ GET /auth/callback           │  verify state, drop cookie   │                 │
     │─────────────────────────────>│  exchange code at ISSUER/token ───────────────> │
     │                              │  verify id_token             │                 │
     │                              │                              │                 │
  5  │                              │  POST /v1/sessions ─────────>│ identity upsert │
     │                              │                              │ session insert  │
     │                              │  <──── token, expiry ────────│ login audit row │
     │                              │                              │                 │
  6  │  302 to the return target    │  Set-Cookie: am_session      │                 │
     │  Set-Cookie: am_session      │                              │                 │
     │<─────────────────────────────│                              │                 │
```

Step 3's browser leg goes to `AGENT_MANAGER_OIDC_BROWSER_BASE_URL`; step 4's backchannel
exchange goes to the issuer. That asymmetry is R2's whole finding, and it is confined to one
function: the one that builds the redirect in step 2.

---

## Routes the web role adds

| Route | Method | Purpose |
| --- | --- | --- |
| `/auth/login` | GET | Mints round-trip state, sets `am_oidc`, redirects to the provider. |
| `/auth/callback` | GET | Validates state, exchanges the code, verifies the ID token, mints the session, sets `am_session`, redirects to the return target. |
| `/auth/logout` | POST | Expires the session server-side, clears the cookie, redirects to `/auth/signin`. **POST, not GET** — a GET sign-out is triggerable by any image tag on any page. |
| `/auth/signin` | GET | The sign-in screen. The only screen a signed-out visitor may render. |

`/healthz`, `/static/*` and `/auth/*` are the complete unauthenticated set. Every other route
requires a resolved session (FR-101 of 001's spirit: the hub has no anonymous view).

---

## Cookies

### `am_session` — the session

| Attribute | Value | Why |
| --- | --- | --- |
| Value | the opaque token `commands.Login` returned | The api stores only its sha256 (`auth.HashToken`). The plaintext exists in the cookie and nowhere else. |
| `HttpOnly` | yes | Script must not read it. |
| `SameSite` | `Lax` | The sign-in redirect is a top-level GET navigation, which `Lax` permits; `Strict` would drop the cookie on the return from the provider. |
| `Secure` | when the hub is served over TLS | Derived from the configured public base URL's scheme, not from the request, so a proxy cannot talk the hub out of it. |
| `Path` | `/` | Every screen needs it. |
| `Max-Age` | the session's TTL, matching the row's `expires_at` | A cookie outliving its row is a guaranteed "you are signed out" surprise. |

### `am_oidc` — the round trip, 90 seconds

Carries the `state` value, the PKCE code verifier and the return target, signed with a key the
web role holds. Signed rather than stored because the web role has no table and the value's
lifetime is one redirect (R3).

| Attribute | Value |
| --- | --- |
| `HttpOnly` | yes |
| `SameSite` | `Lax` |
| `Secure` | as `am_session` |
| `Path` | `/auth/callback` — it is needed at exactly one route |
| `Max-Age` | 90 s |

Deleted the moment the callback reads it, before the code exchange, so a replayed callback finds
nothing (FR-112).

---

## Rules

**State is single-use.** The callback compares the query's `state` against the cookie's in
constant time, then deletes the cookie. A callback with no cookie, a mismatched value, or a
value already consumed is refused with no session issued and no code exchanged.

**PKCE is not optional.** S256. The verifier travels in `am_oidc`; the challenge goes on the
authorization request. It costs one hash and closes code interception on a redirect URI that is
by definition public.

**The return target is a local path or nothing.** Validated by the same rule the theme form's
`return` field already uses: it must begin with a single `/`, must not begin with `//`, and must
contain no scheme or authority. Anything else falls back to `/`. Without this, `/auth/login` is
an open redirect wearing a login button.

**Nothing about the session is trusted from the client except the token.** No role, no identity,
no expiry is read from a cookie. `auth.Sessions.Resolve` re-resolves identity and role from
`group_role_map` on every request, which is what makes FR-118 true without a cache to
invalidate.

**Sign-out is server-side.** `commands.ExpireSession` expires the row; clearing the cookie is a
courtesy to the browser, not the mechanism. A replayed cookie is refused as
`ErrUnauthenticated`, indistinguishable from a token that never existed.

---

## The session-minting operation

`POST /v1/sessions` is the one operation in this system whose caller is a role rather than a
person, and it can mint a session for any subject. It is the feature's sharpest security edge
and is recorded as such in the plan's Complexity Tracking table.

**Required properties**:

- Authenticated by a secret shared between the web and api roles, compared in constant time.
- **Refused entirely when the secret is unset.** No default, no "allow when empty", no
  development escape hatch. An unauthenticated session mint is an account-takeover primitive.
- The secret never reaches a log line, an error message, a span attribute or an audit row.
- Present in exactly two environment blocks and nowhere else in the repository.
- Rate-limited, because a failure here is worth brute-forcing.

**Preferred refinement, to be settled in implementation**: pass the raw ID token rather than
parsed claims, and have the api verify it against the provider itself. Verification then lives
in the role that owns identity, the api stops trusting the web role's parsing, and the shared
secret degrades from *the* control to defence in depth. The plan records this as the better
shape if it survives contact with the code — the cost is a second verifier construction in the
api's bootstrap, which the api already does for the device flow.

---

## What each failure renders

Every one of these is a screen a person can land on, so each gets copy rather than a status
code. Provider-supplied text is escaped (001 FR-055).

| Failure | Renders |
| --- | --- |
| Not signed in, protected route | 302 to `/auth/signin` carrying the requested path as the return target |
| Provider unreachable at sign-in | The sign-in screen states the provider cannot be reached and does **not** offer a button that will fail |
| Provider returned `error=access_denied` (or any error) | The provider's reason, escaped, with a retry link. No session. |
| `state` missing, unknown or replayed | Back to the sign-in screen with a plain explanation. No session, no exchange. |
| Code exchange failed | Sign-in screen, generic message; the underlying error is logged with the correlation id, not shown |
| ID token failed verification | As above. This is the one failure that is never explained to the browser in detail. |
| Session mint refused by the api | Sign-in screen stating the hub could not complete sign-in; logged at error with the correlation id |
| Authenticated, but no mapped role | **Signed in.** A distinct screen state saying they hold no role and what to ask for (FR-117) — never an empty catalog |
| Session expired mid-visit | 302 to sign-in preserving the current path. Not an error. |
| api unreachable on a signed-in page | The screen says the hub's api is unavailable — never an empty result set and never a sign-out (FR-122) |

---

## The signed-out contract for every screen

This is the part that generalises past sign-in, and the reason the current UI is dishonest: the
shell asserts an identity that no screen verified.

1. **No component may render an identity, a role, an email or an avatar except from the resolved
   viewer.** The `Shell` props gain a viewer value; there is no fallback and no default. A
   screen test that wants a signed-in shell must supply one (SC-106).
2. **`Shell` must be constructible in a signed-out state**, and in that state renders no viewer
   chip at all — not a placeholder chip, not initials, not "Guest".
3. **Three states are distinct in copy and in markup**: signed out, signed in with no data, and
   signed in but not permitted. 001's catalog already got this right — `am-empty-auth` with its
   own id, and a comment explaining that the whole risk is a reader or a test mistaking it for
   an empty catalog. Every new screen follows that precedent.
4. **An action the viewer's role does not permit is absent or disabled with its reason**
   (FR-126). Never rendered and then refused by the api.

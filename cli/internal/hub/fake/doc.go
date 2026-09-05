// The shape of this package IS the gate: a fake that diverges from the real
// hub gives green tests and a broken binary. A behavioural test must accept
// [Target] (URL, bearer token, client, content names, optional [Control]),
// never a *fake.Hub directly, or it can never run against the real hub. A
// case the fake can't express says so in the data ([Fixtures] empty,
// [Control] returning [ErrUnsupported]) so the suite skips visibly.

// What this deliberately does NOT do (1/2): import internal/hub's client
// wrapper (it uses hub's generated contract types directly, so a renamed
// field breaks both sides at compile time); serve plaintext under a
// hand-written Digest header (bundles are real zstd, every digest the
// sha256 of served bytes); accept JSON on /v1/device/token (RFC 8628 §3.4
// fixes form-urlencoded).

// (2/2): issue JWTs (tokens are opaque base64url, matching the real hub's
// bearerFormat so a test can't pass one and fail the other); implement the
// four registry operations the CLI never calls; act as a security boundary
// or performance model (tokens live in a map, nothing hashed, no rate
// limiting beyond slow_down).

// Conformance: fake_test.go validates every served lockfile against the
// hub's own schema and re-derives every Digest header independently via
// internal/cache's parser, so this package checks its own agreement with
// the contract.

// Package fake serves the seven hub operations the CLI uses, in process,
// over a real TCP listener, with real zstd bundle bytes and real digests.
package fake

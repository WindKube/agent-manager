// Package fake serves the seven hub operations the CLI uses, in process, over a
// real TCP listener, with real zstd bundle bytes and real digests.
//
// # R5: the shape of this package IS the gate
//
// Research gate R5 (specs/002-agent-manager-cli/plan.md) says: "a fake that
// diverges from the real hub gives green tests and a broken binary. Resolve by
// running the same behavioural suite against both the fake and the compose stack
// ... if a case cannot be expressed against both, it is a case the fake must not
// silently pass."
//
// That is a constraint on this package's API, not a later refactor, and it is why
// the type a behavioural test receives is [Target] — a base URL, a bearer token,
// an HTTP client, the names of the content it may address, and an optional
// [Control] for the parts of a hub no client-facing API exposes. A behavioural
// test must accept a Target and MUST NOT accept a *fake.Hub: the moment a test
// reaches for a method on the fake, that test can never run against T062's
// compose stack, and nothing about it looks wrong.
//
// A hub that cannot express a case says so in the data rather than failing:
// [Fixtures] leaves the field empty and [Control] returns [ErrUnsupported]. The
// suite then skips with a named reason. A skip is visible in the test log; a fake
// that quietly passes a case the real hub fails is not.
//
// # What this package deliberately does NOT do
//
//   - It does not import internal/hub's client wrapper (hub.go, T020). This is a
//     server. It uses the generated CONTRACT TYPES from package hub — the same
//     structs the client decodes into — so a field the hub renamed breaks both
//     sides at compile time. Importing the wrapper would make the fake agree with
//     the client by construction, which is exactly the agreement no test should
//     assume. No import cycle forced this; see the note in fake_test.go about
//     package hub's own tests.
//   - It does not serve plaintext under a hand-written Digest header. A fake that
//     did could not exercise internal/archive (T013) or the digest check (T038) at
//     all, and every test above it would be decorative. Bundles are built with
//     archive/tar and klauspost/compress/zstd at construction, and every digest —
//     lockfile entry and RFC 3230 header alike — is the sha256 of the bytes that
//     are actually served.
//   - It does not accept JSON on /v1/device/token. RFC 8628 §3.4 fixes that body
//     as application/x-www-form-urlencoded and the real hub enforces it, so a fake
//     that also took JSON would pass a test the real hub fails. That is the R5
//     violation in its purest form.
//   - It issues OPAQUE tokens: base64url of 32 random bytes, no dots, no claims.
//     Never a JWT, because a test could then pass against the fake by decoding one
//     and fail against the real hub, whose bearerFormat is `opaque`. A token's
//     lifetime is the expires_in returned beside it and nowhere else.
//   - It does not implement the four package-registry operations. The CLI has no
//     use for them and the generated client excludes them by operation id.
//   - It is not a security boundary and not a performance model. Tokens live in a
//     map, nothing is hashed at rest, and there is no rate limiting beyond
//     slow_down. Do not read this file to learn what the hub stores.
//
// # Conformance
//
// fake_test.go is the self-test R5 asks for: every lockfile this package serves is
// validated against specs/001-agent-manager-hub/contracts/lockfile.schema.json by
// a validator that reads the schema file itself, and every Digest header is
// re-derived from the served bytes through internal/cache's parser — an
// independent second implementation of the same encoding. A fake nobody checks is
// a second implementation of the hub with no tests, which is worse than no fake.
package fake

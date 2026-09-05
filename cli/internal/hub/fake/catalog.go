package fake

import (
	"strings"
	"time"

	"github.com/WindKube/agent-manager/cli/internal/hub"
)

// pkg is one package version the fake can serve bundle bytes for. Publisher
// (a two-segment slug) and namespace (its first segment) are kept distinct
// on purpose — conflating them already shipped as a bug three times
// hub-side — and the bundle path's `{publisher}` param actually takes the
// namespace, so two publishers sharing one namespace are modelled here too.
type pkg struct {
	ID        string // namespace/name
	Version   string
	Publisher string // publisher slug: two segments, first of which is the namespace
	Kind      hub.LockfileEntryKind

	// serve decides what GET /v1/bundles/... does with this package.
	serve serveMode

	blob blob
}

type serveMode int

const (
	serveBytes     serveMode = iota // 200 with the bytes
	serveRedirect                   // 307 to a same-host pre-signed URL
	serveForbidden                  // 403: rejected by the gate, mid-sync

	// serveRedirectStale is the 307 offload path's negative control: the hub
	// answers 307 but the Location's signature is one the object store
	// rejects with 403 — what an expired or clock-skewed pre-signed URL
	// looks like on the wire. A store 403 and a hub 403 mean opposite things
	// (infrastructure failure vs. the scan gate), and this is the only
	// fixture that can tell the two apart.
	serveRedirectStale
)

func (p pkg) namespace() string {
	ns, _, _ := strings.Cut(p.ID, "/")
	return ns
}

func (p pkg) objectKey() string {
	return "bundles/" + p.ID + "/" + p.Version + "/bundle.tar.zst"
}

// digestOverride, when set on an entry, is the digest written into the lockfile
// INSTEAD of the digest of the bytes served. It is a real sha256 of real other
// bytes, never a hand-mangled string, so a client that fails the comparison fails
// it the way it would in production.
type entrySpec struct {
	pkgID          string
	resolution     hub.LockfileEntryResolution
	verdict        hub.LockfileEntryVerdict
	digestOverride string
	signature      *hub.LockfileSignature
	override       *hub.LockfileOverride
}

type revisionSpec struct {
	revision int64
	note     string
	gate     hub.LockfileGate
	policy   hub.LockfileDefaultPolicy
	targets  []hub.LockfileTargets
	entries  []entrySpec
	skipped  []hub.LockfileSkip
}

type profileSpec struct {
	slug       string
	name       string
	visibility hub.LockfileProfileVisibility
	revisions  []revisionSpec // ascending; the last is head
}

// The fixture slugs. Exported through Fixtures so a suite never types one.
const (
	slugBaseline       = "platform-baseline"
	slugDigestMismatch = "digest-mismatch"
	slugForbidden      = "bundle-forbidden"
	slugPresigned      = "presigned-bundles"
	slugPresignedStale = "presigned-stale"
	slugFutureSkip     = "future-skip-reason"
	slugUnwritable     = "unwritable-target"
	slugMissing        = "no-such-profile"
)

// futureSkipReason is outside the frozen schema's enum, on purpose: the CLI
// ships separately from the hub and must report an unrecognised reason
// verbatim rather than drop it. One profile serves this value with the
// enum relaxed only for it, so that is the one deviation the self-test
// asserts is happening.
const futureSkipReason = "quarantined-by-org-policy"

func catalog() []*pkg {
	pkgs := []*pkg{
		{ID: "acme/code-review", Version: "2.4.1", Publisher: "acme/platform", Kind: "skill"},
		{ID: "acme/lint-guard", Version: "1.0.3", Publisher: "acme/security", Kind: "skill"}, // acme again, different publisher
		{ID: "example/doc-writer", Version: "0.9.0", Publisher: "example/platform", Kind: "skill"},
		{ID: "contoso/stale-digest", Version: "1.0.0", Publisher: "contoso/tools", Kind: "skill"},
		{ID: "contoso/gated", Version: "3.1.0", Publisher: "contoso/tools", Kind: "skill", serve: serveForbidden},
		{ID: "contoso/offloaded", Version: "1.2.0", Publisher: "contoso/tools", Kind: "skill", serve: serveRedirect},
		{ID: "contoso/offloaded-stale", Version: "1.2.0", Publisher: "contoso/tools", Kind: "skill", serve: serveRedirectStale},
		{ID: "acme/code-review", Version: "2.4.0", Publisher: "acme/platform", Kind: "skill"}, // older rev, differs in content not just number
	}
	for _, p := range pkgs {
		p.blob = packBundle(skillFiles(p.ID, p.Version))
	}
	return pkgs
}

func profiles() []profileSpec {
	// Which profile gets which target set is load-bearing: naming the
	// unwritable codex target on EVERY profile (an earlier version's
	// approach) refuses every profile the fake serves, leaving nothing for
	// the happy-path/idempotence/interruption tests to run against. Codex
	// gets its own dedicated refusal-profile instead, matching the real
	// hub's own seeded lockfile (claude-code only).
	writable := []hub.LockfileTargets{"claude-code"}
	unwritable := []hub.LockfileTargets{"claude-code", "codex"}
	return []profileSpec{
		{
			slug: slugBaseline, name: "Platform baseline", visibility: "organisation",
			revisions: []revisionSpec{
				{
					revision: 6, note: "Previous quarter", gate: "approval",
					policy: "pinned", targets: writable,
					entries: []entrySpec{
						{pkgID: "acme/code-review@2.4.0", resolution: "pinned", verdict: "clean"},
					},
					skipped: []hub.LockfileSkip{}, // legally empty; exercises both empty and full handling
				},
				{
					revision: 7, note: "Quarterly refresh", gate: "approval",
					policy: "pinned", targets: writable,
					entries: []entrySpec{
						{pkgID: "acme/code-review@2.4.1", resolution: "pinned", verdict: "clean",
							signature: &hub.LockfileSignature{
								Ref: ptr("sigstore:acme/code-review@2.4.1"),
								// False until Sigstore verification ships. The schema's own
								// words: never render a false value as a pass.
								Verified: ptr(false),
							}},
						{pkgID: "acme/lint-guard@1.0.3", resolution: "latest", verdict: "flagged",
							override: &hub.LockfileOverride{
								Reviewer:  "security-lead@example.dev",
								Note:      "Network call is to our own registry",
								ExpiresAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
							}},
						{pkgID: "example/doc-writer@0.9.0", resolution: "range", verdict: "clean"},
					},
					// Three of the six legal reasons. Every one of these must reach the
					// user with the hub's own wording.
					skipped: []hub.LockfileSkip{
						{Id: "acme/legacy-helper", Reason: "flagged-awaiting-approval",
							Detail: ptr("SH-NET-002 in postinstall.sh"), WouldHaveResolvedTo: ptr("1.9.0")},
						{Id: "example/old-formatter", Reason: "version-rejected",
							Detail: ptr("3.0.0 was withdrawn by the publisher")},
						{Id: "contoso/pinned-away", Reason: "pin-target-missing",
							WouldHaveResolvedTo: ptr("2.0.0")},
					},
				},
			},
		},
		{
			slug: slugDigestMismatch, name: "Digest mismatch", visibility: "private",
			revisions: []revisionSpec{{
				revision: 1, gate: "block", targets: writable,
				entries: []entrySpec{
					{pkgID: "acme/code-review@2.4.1", resolution: "pinned", verdict: "clean"},
					{pkgID: "contoso/stale-digest@1.0.0", resolution: "pinned", verdict: "clean",
						digestOverride: "acme/lint-guard@1.0.3"}, // a different bundle's real digest, not a mangled string
				},
				skipped: []hub.LockfileSkip{},
			}},
		},
		{
			slug: slugForbidden, name: "Gated bundle", visibility: "organisation",
			revisions: []revisionSpec{{
				revision: 2, gate: "block", targets: writable,
				// order matters: installable, 403, installable — tests that an abort mid-sync leaves the third uninstalled
				entries: []entrySpec{
					{pkgID: "acme/code-review@2.4.1", resolution: "pinned", verdict: "clean"},
					{pkgID: "contoso/gated@3.1.0", resolution: "pinned", verdict: "flagged"},
					{pkgID: "example/doc-writer@0.9.0", resolution: "pinned", verdict: "clean"},
				},
				skipped: []hub.LockfileSkip{},
			}},
		},
		{
			slug: slugPresigned, name: "Pre-signed bundles", visibility: "organisation",
			revisions: []revisionSpec{{
				revision: 1, gate: "warn-with-override", targets: writable,
				entries: []entrySpec{
					{pkgID: "contoso/offloaded@1.2.0", resolution: "pinned", verdict: "clean"},
				},
				skipped: []hub.LockfileSkip{},
			}},
		},
		{
			// negative control: entry 2's 307 target refuses; misreading that store 403 as the hub's scan gate must not exit 0
			slug: slugPresignedStale, name: "Pre-signed bundle whose signature the store rejects",
			visibility: "organisation",
			revisions: []revisionSpec{{
				revision: 1, gate: "warn-with-override", targets: writable,
				entries: []entrySpec{
					{pkgID: "acme/code-review@2.4.1", resolution: "pinned", verdict: "clean"},
					{pkgID: "contoso/offloaded-stale@1.2.0", resolution: "pinned", verdict: "clean"},
				},
				skipped: []hub.LockfileSkip{},
			}},
		},
		{
			// ErrR2Unresolved: a target this client can't write must be refused by name, never silently skipped
			slug: slugUnwritable, name: "Names an unwritable target", visibility: "organisation",
			revisions: []revisionSpec{{
				revision: 1, gate: "approval", policy: "pinned", targets: unwritable,
				entries: []entrySpec{
					{pkgID: "acme/code-review@2.4.1", resolution: "pinned", verdict: "clean"},
				},
				skipped: []hub.LockfileSkip{},
			}},
		},
		{
			slug: slugFutureSkip, name: "Unknown skip reason", visibility: "organisation",
			revisions: []revisionSpec{{
				revision: 1, gate: "approval", targets: writable,
				entries: []entrySpec{
					{pkgID: "acme/code-review@2.4.1", resolution: "pinned", verdict: "clean"},
				},
				skipped: []hub.LockfileSkip{
					{Id: "acme/from-the-future", Reason: futureSkipReason,
						Detail: ptr("a reason this build of amctl has never heard of")},
				},
			}},
		},
	}
}

func ptr[T any](v T) *T { return &v }

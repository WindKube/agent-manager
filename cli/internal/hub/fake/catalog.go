package fake

import (
	"strings"
	"time"

	"github.com/WindKube/agent-manager/cli/internal/hub"
)

// pkg is one package version the fake can serve bundle bytes for.
//
// Publisher is here and Namespace is derived from ID, because the two are NOT the
// same thing and conflating them is the bug class CLI-CONTRACT.md says has already
// shipped and been fixed three times on the hub side. A publisher SLUG is two
// segments (`acme/platform`); a NAMESPACE is that slug's first segment (`acme`);
// a lockfile entry's `id` is `namespace/name`. The bundle path's `{publisher}`
// parameter takes the NAMESPACE despite its name.
//
// Two publishers sharing one namespace is legal and is modelled here on purpose:
// FR-023 requires distinct destination directories per `namespace/name`, and a
// catalog with one publisher per namespace cannot exercise it — every test would
// pass under an implementation that keyed off the publisher instead.
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
	slugFutureSkip     = "future-skip-reason"
	slugMissing        = "no-such-profile"
)

// futureSkipReason is a value the frozen schema's enum does not contain.
//
// FR-011 requires the CLI to report an unrecognised reason VERBATIM rather than
// drop it, because the hub may add one and this client ships separately from it.
// A fake that only ever served the six legal values could not exercise that, so
// one profile serves this and the conformance self-test validates that profile
// with the reason enum relaxed — asserting that the ONLY schema deviation is the
// one this constant is for.
const futureSkipReason = "quarantined-by-org-policy"

func catalog() []*pkg {
	pkgs := []*pkg{
		// Namespace `acme`, publisher `acme/platform`.
		{ID: "acme/code-review", Version: "2.4.1", Publisher: "acme/platform", Kind: "skill"},
		// Namespace `acme` AGAIN, different publisher. FR-023's case.
		{ID: "acme/lint-guard", Version: "1.0.3", Publisher: "acme/security", Kind: "skill"},
		{ID: "example/doc-writer", Version: "0.9.0", Publisher: "example/platform", Kind: "skill"},
		{ID: "contoso/stale-digest", Version: "1.0.0", Publisher: "contoso/tools", Kind: "skill"},
		{ID: "contoso/gated", Version: "3.1.0", Publisher: "contoso/tools", Kind: "skill", serve: serveForbidden},
		{ID: "contoso/offloaded", Version: "1.2.0", Publisher: "contoso/tools", Kind: "skill", serve: serveRedirect},
		// An older revision of code-review, so `head` and a pinned revision differ
		// in content and not merely in number.
		{ID: "acme/code-review", Version: "2.4.0", Publisher: "acme/platform", Kind: "skill"},
	}
	for _, p := range pkgs {
		p.blob = packBundle(skillFiles(p.ID, p.Version))
	}
	return pkgs
}

func profiles() []profileSpec {
	// Both contract targets, deliberately, even though R2 ships only claude-code:
	// the fake serves what the hub may serve, and a lockfile naming a target the
	// client cannot write is the case FR-011 and layout's ErrR2Unresolved exist for.
	// A fake that only ever names the shipped target cannot exercise the refusal.
	claudeCode := []hub.LockfileTargets{"claude-code", "codex"}
	return []profileSpec{
		{
			slug: slugBaseline, name: "Platform baseline", visibility: "organisation",
			revisions: []revisionSpec{
				{
					revision: 6, note: "Previous quarter", gate: "approval",
					policy: "pinned", targets: claudeCode,
					entries: []entrySpec{
						{pkgID: "acme/code-review@2.4.0", resolution: "pinned", verdict: "clean"},
					},
					// Legally empty. Serving one profile with an empty skipped array
					// and one with a full array is the only way a client's handling
					// of both is exercised.
					skipped: []hub.LockfileSkip{},
				},
				{
					revision: 7, note: "Quarterly refresh", gate: "approval",
					policy: "pinned", targets: claudeCode,
					entries: []entrySpec{
						{pkgID: "acme/code-review@2.4.1", resolution: "pinned", verdict: "clean",
							signature: &hub.LockfileSignature{
								Ref: ptr("sigstore:acme/code-review@2.4.1"),
								// FR-048a: false until Sigstore verification ships. The
								// schema's own words: never render a false value as a pass.
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
					// user with the hub's own wording (FR-011).
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
				revision: 1, gate: "block", targets: claudeCode,
				entries: []entrySpec{
					{pkgID: "acme/code-review@2.4.1", resolution: "pinned", verdict: "clean"},
					// The digest of a DIFFERENT real bundle. Both sides are genuine
					// sha256 values, so the client's comparison fails for the
					// production reason and not because a string was mangled.
					{pkgID: "contoso/stale-digest@1.0.0", resolution: "pinned", verdict: "clean",
						digestOverride: "acme/lint-guard@1.0.3"},
				},
				skipped: []hub.LockfileSkip{},
			}},
		},
		{
			slug: slugForbidden, name: "Gated bundle", visibility: "organisation",
			revisions: []revisionSpec{{
				revision: 2, gate: "block", targets: claudeCode,
				// Order matters: one installable entry, then the 403, then another
				// installable entry. A sync that aborts on the 403 leaves the third
				// uninstalled, which is what FR-011's mid-sync case is about.
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
				revision: 1, gate: "warn-with-override", targets: claudeCode,
				entries: []entrySpec{
					{pkgID: "contoso/offloaded@1.2.0", resolution: "pinned", verdict: "clean"},
				},
				skipped: []hub.LockfileSkip{},
			}},
		},
		{
			slug: slugFutureSkip, name: "Unknown skip reason", visibility: "organisation",
			revisions: []revisionSpec{{
				revision: 1, gate: "approval", targets: claudeCode,
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

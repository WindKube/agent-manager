package fake

import (
	"strings"
	"time"

	"github.com/WindKube/agent-manager/cli/internal/hub"
)

// pkg is one package version the fake can serve. Publisher and namespace are kept distinct, since the
// bundle path's `{publisher}` param actually takes the namespace.
type pkg struct {
	ID        string // namespace/name
	Version   string
	Publisher string // publisher slug: two segments, first of which is the namespace
	Kind      hub.LockfileEntryKind

	serve serveMode

	blob blob
}

type serveMode int

const (
	serveBytes     serveMode = iota // 200 with the bytes
	serveRedirect                   // 307 to a same-host pre-signed URL
	serveForbidden                  // 403: rejected by the gate, mid-sync

	// serveRedirectStale answers 307 to a URL the object store rejects with 403, as an expired
	// pre-signed URL would; it tells a store 403 from the hub's scan gate.
	serveRedirectStale
)

func (p pkg) namespace() string {
	ns, _, _ := strings.Cut(p.ID, "/")
	return ns
}

func (p pkg) objectKey() string {
	return "bundles/" + p.ID + "/" + p.Version + "/bundle.tar.zst"
}

// digestOverride, when set, locks a real digest of another bundle instead of the bytes served.
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
	slugBothTargets    = "both-targets"
	slugPlugin         = "every-target-plugin"
	slugMissing        = "no-such-profile"
)

// futureSkipReason is deliberately outside the schema's enum: the CLI must report an unrecognised
// reason verbatim. It is the one schema deviation the self-test allows.
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
		{ID: "acme/toolkit", Version: "1.0.0", Publisher: "acme/platform", Kind: "plugin"},
	}
	for _, p := range pkgs {
		if p.Kind == hub.Plugin {
			p.blob = packBundle(pluginFiles(p.ID, p.Version))
			continue
		}
		p.blob = packBundle(skillFiles(p.ID, p.Version))
	}
	return pkgs
}

func profiles() []profileSpec {
	// Most profiles name claude-code only, as the real hub's seed does; one names two targets.
	writable := []hub.LockfileTargets{"claude-code"}
	both := []hub.LockfileTargets{"claude-code", "codex"}
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
								// False until Sigstore verification ships.
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
			slug: slugBothTargets, name: "Names two targets", visibility: "organisation",
			revisions: []revisionSpec{{
				revision: 1, gate: "approval", policy: "pinned", targets: both,
				entries: []entrySpec{
					{pkgID: "acme/code-review@2.4.1", resolution: "pinned", verdict: "clean"},
				},
				skipped: []hub.LockfileSkip{},
			}},
		},
		{
			slug: slugPlugin, name: "A plugin for every target", visibility: "organisation",
			revisions: []revisionSpec{{
				revision: 1, gate: "approval", policy: "pinned",
				targets: []hub.LockfileTargets{"claude-code", "codex", "opencode"},
				entries: []entrySpec{
					{pkgID: "acme/toolkit@1.0.0", resolution: "pinned", verdict: "clean"},
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

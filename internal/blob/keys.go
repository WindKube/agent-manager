package blob

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The key layout is the design's (docs/design/agent-manager.dc.html, the Storage
// screen's keyTree) and FR-006's:
//
//	skills/<namespace>/<name>/<semver>/bundle.tar.zst
//	                                  /plugin.json      (or SKILL.md)
//	                                  /scan.json
//	                                  /signature.sig
//	skills/<namespace>/<name>/index.json    <- version list + latest pointer
//	profiles/<slug>/r<seq>.json
//	profiles/<slug>/head.json
const (
	SkillsPrefix   = "skills"
	ProfilesPrefix = "profiles"

	// StagingPrefix holds a version's parts until index.json names them. It is a
	// sibling of skills/ rather than a child so that listing the catalog can never
	// walk half-written bytes.
	StagingPrefix = "_staging"

	BundleObject        = "bundle.tar.zst"
	ManifestObject      = "plugin.json"
	SkillManifestObject = "SKILL.md"
	ScanObject          = "scan.json"
	SignatureObject     = "signature.sig"
	IndexObject         = "index.json"
	HeadObject          = "head.json"
)

// segmentPattern is what a single path segment may contain.
//
// THE FIRST SEGMENT IS THE NAMESPACE, NOT THE PUBLISHER SLUG, and this field was
// called Publisher until it collided with reality. A publisher is `example/platform`
// and its namespace is `example`; the design's keyTree reads
// `skills/example/terraform-module-review/2.4.1/…` and its package ids read
// `example/pii-redactor`, so both are built from the namespace. Passing a slug here
// is refused by validSegment below, because a slug contains a `/` — which is how the
// confusion surfaces if it comes back.
//
// Namespaces, package names and semvers all arrive from user-supplied
// sources — an uploaded manifest, a repository URL — so a key built from them is
// untrusted input (constitution principle III). Anything that could climb out of
// its prefix is rejected rather than sanitised: a segment must start
// alphanumerically, which alone rules out "", ".", ".." and a leading slash, and
// may then hold only characters a semver or a slug legitimately needs.
var segmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

func validSegment(kind, s string) error {
	if !segmentPattern.MatchString(s) {
		return fmt.Errorf("%s %q is not a valid object-key segment", kind, s)
	}
	if strings.Contains(s, "..") {
		return fmt.Errorf("%s %q contains a parent-directory reference", kind, s)
	}
	return nil
}

// PackageRef names one package's prefix in the store.
type PackageRef struct {
	Namespace string
	Name      string
}

func (p PackageRef) Validate() error {
	if err := validSegment("namespace", p.Namespace); err != nil {
		return err
	}
	return validSegment("package name", p.Name)
}

func (p PackageRef) Prefix() string {
	return SkillsPrefix + "/" + p.Namespace + "/" + p.Name
}

// IndexKey is the commit-last pointer: the version list and the latest pointer.
func (p PackageRef) IndexKey() string { return p.Prefix() + "/" + IndexObject }

func (p PackageRef) String() string { return p.Namespace + "/" + p.Name }

// VersionRef names one immutable version's prefix.
type VersionRef struct {
	Namespace string
	Name      string
	Semver    string
}

func (v VersionRef) Package() PackageRef {
	return PackageRef{Namespace: v.Namespace, Name: v.Name}
}

func (v VersionRef) Validate() error {
	if err := v.Package().Validate(); err != nil {
		return err
	}
	return validSegment("semver", v.Semver)
}

func (v VersionRef) Prefix() string { return v.Package().Prefix() + "/" + v.Semver }

// Key is the final key of one object inside the version's prefix.
func (v VersionRef) Key(object string) string { return v.Prefix() + "/" + object }

func (v VersionRef) BundleKey() string { return v.Key(BundleObject) }

func (v VersionRef) String() string { return v.Package().String() + "@" + v.Semver }

// stagingKey is where one part waits until index.json names the version. attempt
// makes two concurrent publishes of the same version write to different prefixes,
// so one cannot promote the other's bytes.
func stagingKey(v VersionRef, attempt, object string) string {
	return StagingPrefix + "/" + v.Namespace + "/" + v.Name + "/" + v.Semver + "/" + attempt + "/" + object
}

// ProfileRevisionKey is profiles/<slug>/r<seq>.json — the resolved lockfile.
// A slug may itself be several segments (the design shows
// profiles/example/platform-engineer/), so each one is validated.
func ProfileRevisionKey(slug string, seq int) (string, error) {
	prefix, err := profilePrefix(slug)
	if err != nil {
		return "", err
	}
	if seq < 1 {
		return "", fmt.Errorf("revision seq %d is not positive", seq)
	}
	return prefix + "/r" + strconv.Itoa(seq) + ".json", nil
}

// ProfileHeadKey is profiles/<slug>/head.json — the pointer to the current
// revision, written after the revision it names, for the same reason index.json
// is written after a version's bytes.
func ProfileHeadKey(slug string) (string, error) {
	prefix, err := profilePrefix(slug)
	if err != nil {
		return "", err
	}
	return prefix + "/" + HeadObject, nil
}

func profilePrefix(slug string) (string, error) {
	if slug == "" {
		return "", fmt.Errorf("profile slug is empty")
	}
	for _, segment := range strings.Split(slug, "/") {
		if err := validSegment("profile slug segment", segment); err != nil {
			return "", err
		}
	}
	return ProfilesPrefix + "/" + slug, nil
}

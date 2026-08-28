package models

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// catalog_entry (data-model.md, R12) is deliberately absent. It is the one
// projection principle VIII sanctions, and it is only built if measurement shows
// the base tables miss SC-003's 300 ms p95 at 10k packages / 50k versions. A
// projection is a permanent consistency liability, so the allowance stays
// unspent until the measurement says otherwise.

// Publisher owns packages. `verified` is set by a catalog admin and is never
// inferred from the slug prefix — which is what keeps the namespace and the
// verified flag two different things, and lets community/octoflow be verified
// after review.
//
// There is no Namespace field here, and that is deliberate. publisher.namespace
// exists in the database as a STORED GENERATED column, split_part(slug, '/', 1),
// so it cannot drift from the slug; a bun tag cannot express `generated always
// as`, and a plain column here would make 02-tables.sql create an ordinary one
// that 03-constraints.sql could not then convert. Nothing in Go needs to read it:
// a query derives the namespace with split_part, which is the same string by
// definition. The column exists so that package.namespace has something to be
// held to by a foreign key.
type Publisher struct {
	bun.BaseModel `bun:"table:publisher,alias:pub"`

	ID uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	// Slug is the whole two-segment owner, `example/platform`. The two-segment
	// shape is a check constraint, not a convention: the first segment is the
	// object-key prefix, so a one-segment slug would produce keys nothing else in
	// the system expects.
	Slug        string    `bun:"slug,type:text,notnull,unique"`
	DisplayName string    `bun:"display_name,type:text,notnull"`
	Verified    bool      `bun:"verified,type:boolean,notnull,default:false"`
	CreatedAt   time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt   time.Time `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Packages []*Package `bun:"rel:has-many,join:id=publisher_id"`
}

// Category is admin-curated (FR-049). Tags are not categories: they are free-form
// strings on the version.
type Category struct {
	bun.BaseModel `bun:"table:category,alias:cat"`

	ID        uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	Name      string    `bun:"name,type:text,notnull,unique"`
	Slug      string    `bun:"slug,type:text,notnull,unique"`
	CreatedAt time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt time.Time `bun:"updated_at,type:timestamptz,notnull,default:now()"`
}

// Package is the named unit a publisher owns.
//
// Uniqueness is `(namespace, name)`, NOT `(publisher_id, name)`. The weaker key
// permits example/platform and example/security to each own pii-redactor; both
// render as the id example/pii-redactor and both resolve to the object key
// skills/example/pii-redactor/..., so one bundle silently overwrites the other.
// Against FR-007's immutability premise that is a correctness bug, not a display
// one. The new key is strictly stronger — two packages with the same namespace
// and name are rejected whichever publisher owns them — so the old one is
// redundant rather than merely weaker, and is gone.
type Package struct {
	bun.BaseModel `bun:"table:package,alias:pkg"`

	ID          uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	PublisherID uuid.UUID `bun:"publisher_id,type:uuid,notnull"`
	// Namespace is the first segment of the owning publisher's slug, denormalised
	// so `unique (namespace, name)` can be a plain constraint. It is not free to
	// disagree with its publisher: a composite foreign key
	// (publisher_id, namespace) -> publisher (id, namespace) holds it, which is
	// what makes the denormalisation safe declaratively rather than by trigger.
	Namespace  string            `bun:"namespace,type:text,notnull,unique:package_namespace_name"`
	Name       string            `bun:"name,type:text,notnull,unique:package_namespace_name"`
	Kind       PackageKind       `bun:"kind,type:package_kind,notnull"`
	CategoryID *uuid.UUID        `bun:"category_id,type:uuid,nullzero"`
	Visibility PackageVisibility `bun:"visibility,type:package_visibility,notnull"`
	// ParentPackageID is set when a skill is distributed inside a plugin, which is
	// what the origin line in FR-016 renders.
	ParentPackageID *uuid.UUID `bun:"parent_package_id,type:uuid,nullzero"`
	// LatestVersionID is a denormalised pointer maintained on publish. It carries
	// no bun relation on purpose: version already belongs-to package, and a second
	// relation in the other direction makes the Atlas loader's topological sort a
	// cycle. The migration layer adds the foreign key.
	LatestVersionID *uuid.UUID `bun:"latest_version_id,type:uuid,nullzero"`
	CreatedAt       time.Time  `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt       time.Time  `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Publisher *Publisher `bun:"rel:belongs-to,join:publisher_id=id"`
	Category  *Category  `bun:"rel:belongs-to,join:category_id=id"`
	Parent    *Package   `bun:"rel:belongs-to,join:parent_package_id=id"`
	Versions  []*Version `bun:"rel:has-many,join:id=package_id"`
}

// Version is append-only: bytes, digest and manifest for one immutable release.
type Version struct {
	bun.BaseModel `bun:"table:version,alias:ver"`

	ID        uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	PackageID uuid.UUID `bun:"package_id,type:uuid,notnull,unique:version_package_semver"`
	Semver    string    `bun:"semver,type:text,notnull,unique:version_package_semver"`
	// SemverSort is the zero-padded key from SemverSort, so ordering releases is an
	// index scan rather than a Go sort.
	SemverSort string `bun:"semver_sort,type:text,notnull"`
	ObjectKey  string `bun:"object_key,type:text,notnull"`
	// Digest is sha256 of the bundle, so 32 bytes. Postgres bytea carries no
	// length, so the width is a check constraint in the migration layer.
	Digest    []byte          `bun:"digest,type:bytea,nullzero"`
	SizeBytes *int64          `bun:"size_bytes,type:bigint,nullzero"`
	Manifest  json.RawMessage `bun:"manifest,type:jsonb,notnull"`
	// Tags materialises this version's version_tag rows so the catalog query can
	// use a GIN index instead of a join (R4).
	Tags    []string `bun:"tags,array,type:text[],notnull,default:'{}'"`
	DistTag DistTag  `bun:"dist_tag,type:dist_tag,notnull"`
	Verdict Verdict  `bun:"verdict,type:verdict,notnull"`
	// Visible is commit-last (FR-008): flipped true only once bytes, digest and
	// metadata have all landed.
	Visible   bool      `bun:"visible,type:boolean,notnull,default:false"`
	CreatedAt time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Package      *Package      `bun:"rel:belongs-to,join:package_id=id"`
	VersionTags  []*VersionTag `bun:"rel:has-many,join:id=version_id"`
	Components   []*Component  `bun:"rel:has-many,join:id=version_id"`
	Capabilities []*Capability `bun:"rel:has-many,join:id=version_id"`
	Signature    *Signature    `bun:"rel:has-one,join:id=version_id"`
}

// VersionTag holds the free-form keywords read from the manifest. Tags belong to
// the version, not the package, because they can change between versions (R1).
type VersionTag struct {
	bun.BaseModel `bun:"table:version_tag,alias:vtag"`

	VersionID uuid.UUID `bun:"version_id,pk,type:uuid,notnull"`
	Tag       string    `bun:"tag,pk,type:text,notnull"`
	CreatedAt time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Version *Version `bun:"rel:belongs-to,join:version_id=id"`
}

// Component is derived from the bundle's file tree, not from the manifest: no
// manifest field enumerates components (R1). The path is unique within a tree,
// which is why it is the rest of the key.
type Component struct {
	bun.BaseModel `bun:"table:component,alias:cmp"`

	VersionID uuid.UUID     `bun:"version_id,pk,type:uuid,notnull"`
	Path      string        `bun:"path,pk,type:text,notnull"`
	Kind      ComponentKind `bun:"kind,type:component_kind,notnull"`
	Name      string        `bun:"name,type:text,notnull"`
	Note      string        `bun:"note,type:text,nullzero"`
	CreatedAt time.Time     `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Version *Version `bun:"rel:belongs-to,join:version_id=id"`
}

// Capability records what a version can reach. `inferred` rows come from the
// scanner, `expected` rows from the manifest's extensions block; a finding is
// raised where inferred exceeds expected (FR-027), so both live in one table
// keyed by source.
type Capability struct {
	bun.BaseModel `bun:"table:capability,alias:cap"`

	VersionID uuid.UUID        `bun:"version_id,pk,type:uuid,notnull"`
	Source    CapabilitySource `bun:"source,pk,type:capability_source,notnull"`
	Name      string           `bun:"name,pk,type:text,notnull"`
	Detail    json.RawMessage  `bun:"detail,type:jsonb,nullzero"`
	Level     CapabilityLevel  `bun:"level,type:capability_level,notnull"`
	CreatedAt time.Time        `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Version *Version `bun:"rel:belongs-to,join:version_id=id"`
}

// Signature is registry-side metadata, never a manifest field (R9). The
// `require signed bundles` policy checks ref is not null; verified_at, verified_by
// and result stay null until sigstore-go lands, and the UI must say so (FR-048a).
type Signature struct {
	bun.BaseModel `bun:"table:signature,alias:sig"`

	VersionID  uuid.UUID        `bun:"version_id,pk,type:uuid,notnull"`
	Ref        string           `bun:"ref,type:text,nullzero"`
	Kind       SignatureKind    `bun:"kind,type:signature_kind,notnull"`
	VerifiedAt *time.Time       `bun:"verified_at,type:timestamptz,nullzero"`
	VerifiedBy string           `bun:"verified_by,type:text,nullzero"`
	Result     *SignatureResult `bun:"result,type:signature_result,nullzero"`
	CreatedAt  time.Time        `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt  time.Time        `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Version *Version `bun:"rel:belongs-to,join:version_id=id"`
}

// semverSortNumberWidth is the zero-padded width of major, minor and patch.
const semverSortNumberWidth = 10

// semverSortIdentWidth is the padded width of one prerelease identifier.
const semverSortIdentWidth = 20

// semverSortPad is the padding for alphanumeric prerelease identifiers. It is the
// lowest character semver permits in an identifier ('-' is 0x2D, below '0'), so a
// short identifier sorts before a longer one that starts with it — which is what
// semver requires.
const semverSortPad = "-"

// SemverSort computes version.semver_sort: a key whose byte order is semver's
// precedence order, so `order by semver_sort desc` is an index scan.
//
// The key is major/minor/patch zero-padded, then one flag digit that is '0' when
// a prerelease is present and '1' when it is not — that single digit is what puts
// 1.0.0-rc.1 before 1.0.0. Each prerelease identifier then contributes a kind
// digit ('0' numeric, '1' alphanumeric, so numeric identifiers sort first) plus a
// padded payload. Build metadata is dropped: semver says it does not affect
// precedence.
//
// The key alphabet is [0-9A-Za-z-] only, which orders the same under C and under
// en_US.utf8 (both verified against Postgres 16). Declaring the column `collate
// "C"` makes that independent of the cluster's locale.
func SemverSort(semver string) (string, error) {
	core := strings.TrimPrefix(strings.TrimSpace(semver), "v")
	if core == "" {
		return "", fmt.Errorf("semver sort %q: empty", semver)
	}
	if i := strings.IndexByte(core, '+'); i >= 0 {
		core = core[:i]
	}

	var (
		prerelease    string
		hasPrerelease bool
	)
	if i := strings.IndexByte(core, '-'); i >= 0 {
		core, prerelease, hasPrerelease = core[:i], core[i+1:], true
	}

	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("semver sort %q: want major.minor.patch, got %d parts", semver, len(parts))
	}

	var key strings.Builder
	for _, part := range parts {
		padded, err := paddedNumber(part, semverSortNumberWidth)
		if err != nil {
			return "", fmt.Errorf("semver sort %q: %w", semver, err)
		}
		key.WriteString(padded)
	}

	if !hasPrerelease {
		key.WriteByte('1')
		return key.String(), nil
	}
	if prerelease == "" {
		return "", fmt.Errorf("semver sort %q: trailing hyphen with no prerelease", semver)
	}
	key.WriteByte('0')

	for _, ident := range strings.Split(prerelease, ".") {
		switch {
		case ident == "":
			return "", fmt.Errorf("semver sort %q: empty prerelease identifier", semver)
		case isNumericIdent(ident):
			padded, err := paddedNumber(ident, semverSortIdentWidth)
			if err != nil {
				return "", fmt.Errorf("semver sort %q: %w", semver, err)
			}
			key.WriteByte('0')
			key.WriteString(padded)
		default:
			if err := validAlnumIdent(ident); err != nil {
				return "", fmt.Errorf("semver sort %q: %w", semver, err)
			}
			if len(ident) > semverSortIdentWidth {
				return "", fmt.Errorf("semver sort %q: prerelease identifier %q is longer than %d", semver, ident, semverSortIdentWidth)
			}
			key.WriteByte('1')
			key.WriteString(ident)
			key.WriteString(strings.Repeat(semverSortPad, semverSortIdentWidth-len(ident)))
		}
	}

	return key.String(), nil
}

// paddedNumber left-pads a semver numeric identifier with zeros to width. It
// refuses anything that would not compare correctly at that width: a non-number,
// a leading zero (semver forbids it, and it would make two spellings of one
// number produce two keys), or a value too wide to pad.
func paddedNumber(s string, width int) (string, error) {
	switch {
	case !isNumericIdent(s):
		return "", fmt.Errorf("%q is not a number", s)
	case len(s) > 1 && s[0] == '0':
		return "", fmt.Errorf("%q has a leading zero", s)
	case len(s) > width:
		return "", fmt.Errorf("%q has more than %d digits", s, width)
	}
	if _, err := strconv.ParseUint(s, 10, 64); err != nil {
		return "", fmt.Errorf("%q does not fit a uint64: %w", s, err)
	}
	return strings.Repeat("0", width-len(s)) + s, nil
}

func isNumericIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validAlnumIdent(s string) error {
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
		default:
			return fmt.Errorf("prerelease identifier %q holds %q", s, string(c))
		}
	}
	return nil
}

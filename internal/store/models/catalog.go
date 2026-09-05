package models

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Publisher owns packages. `verified` is set by a catalog admin and is never
// inferred from the slug prefix.
//
// There is no Namespace field here: publisher.namespace exists in the database
// as a STORED GENERATED column (split_part(slug, '/', 1)) because a bun tag
// cannot express `generated always as`; it exists only so package.namespace has
// something to be held to by a foreign key.
type Publisher struct {
	bun.BaseModel `bun:"table:publisher,alias:pub"`

	ID uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	// Slug is the whole two-segment owner, `example/platform`: the first segment
	// is the object-key prefix, so a one-segment slug would break it.
	Slug        string    `bun:"slug,type:text,notnull,unique"`
	DisplayName string    `bun:"display_name,type:text,notnull"`
	Verified    bool      `bun:"verified,type:boolean,notnull,default:false"`
	CreatedAt   time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt   time.Time `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Packages []*Package `bun:"rel:has-many,join:id=publisher_id"`
}

// Category is admin-curated. Tags are not categories: they are free-form
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
// Uniqueness is `(namespace, name)`, not `(publisher_id, name)`: two publishers
// could otherwise both own a package that renders as the same id and resolves
// to the same object key, so one bundle would silently overwrite the other.
type Package struct {
	bun.BaseModel `bun:"table:package,alias:pkg"`

	ID          uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	PublisherID uuid.UUID `bun:"publisher_id,type:uuid,notnull"`
	// Namespace is denormalised from the owning publisher's slug so `unique
	// (namespace, name)` can be a plain constraint; a composite foreign key
	// (publisher_id, namespace) -> publisher (id, namespace) keeps it from
	// disagreeing with the publisher.
	Namespace  string            `bun:"namespace,type:text,notnull,unique:package_namespace_name"`
	Name       string            `bun:"name,type:text,notnull,unique:package_namespace_name"`
	Kind       PackageKind       `bun:"kind,type:package_kind,notnull"`
	CategoryID *uuid.UUID        `bun:"category_id,type:uuid,nullzero"`
	Visibility PackageVisibility `bun:"visibility,type:package_visibility,notnull"`
	// ParentPackageID is set when a skill is distributed inside a plugin.
	ParentPackageID *uuid.UUID `bun:"parent_package_id,type:uuid,nullzero"`
	// LatestVersionID carries no bun relation on purpose: version already
	// belongs-to package, and a relation back would make the Atlas loader's
	// topological sort a cycle.
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
	// SemverSort orders releases via an index scan rather than a Go sort.
	SemverSort string `bun:"semver_sort,type:text,notnull"`
	ObjectKey  string `bun:"object_key,type:text,notnull"`
	// Digest is sha256 of the bundle, so 32 bytes. Postgres bytea carries no
	// length, so the width is a check constraint in the migration layer.
	Digest    []byte          `bun:"digest,type:bytea,nullzero"`
	SizeBytes *int64          `bun:"size_bytes,type:bigint,nullzero"`
	Manifest  json.RawMessage `bun:"manifest,type:jsonb,notnull"`
	// Tags materialises this version's version_tag rows so the catalog query can
	// use a GIN index instead of a join.
	Tags    []string `bun:"tags,array,type:text[],notnull,default:'{}'"`
	DistTag DistTag  `bun:"dist_tag,type:dist_tag,notnull"`
	Verdict Verdict  `bun:"verdict,type:verdict,notnull"`
	// Visible is commit-last: flipped true only once bytes, digest and metadata
	// have all landed.
	Visible   bool      `bun:"visible,type:boolean,notnull,default:false"`
	CreatedAt time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Package      *Package      `bun:"rel:belongs-to,join:package_id=id"`
	VersionTags  []*VersionTag `bun:"rel:has-many,join:id=version_id"`
	Components   []*Component  `bun:"rel:has-many,join:id=version_id"`
	Capabilities []*Capability `bun:"rel:has-many,join:id=version_id"`
	Signature    *Signature    `bun:"rel:has-one,join:id=version_id"`
}

// VersionTag holds the free-form keywords read from the manifest. Tags belong to
// the version, not the package, because they can change between versions.
type VersionTag struct {
	bun.BaseModel `bun:"table:version_tag,alias:vtag"`

	VersionID uuid.UUID `bun:"version_id,pk,type:uuid,notnull"`
	Tag       string    `bun:"tag,pk,type:text,notnull"`
	CreatedAt time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Version *Version `bun:"rel:belongs-to,join:version_id=id"`
}

// Component is derived from the bundle's file tree, not from the manifest: no
// manifest field enumerates components. The path is unique within a tree, which
// is why it is the rest of the key.
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
// raised where inferred exceeds expected, so both live in one table keyed by
// source.
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

// Signature is registry-side metadata, never a manifest field. The `require
// signed bundles` policy checks ref is not null; verified_at, verified_by and
// result stay null until sigstore-go lands.
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

const semverSortNumberWidth = 10

const semverSortIdentWidth = 20

// semverSortPad is the padding for alphanumeric prerelease identifiers. It is the
// lowest character semver permits in an identifier ('-' is 0x2D, below '0'), so a
// short identifier sorts before a longer one that starts with it — which is what
// semver requires.
const semverSortPad = "-"

// SemverSort computes version.semver_sort: a key whose byte order is semver's
// precedence order, so `order by semver_sort desc` is an index scan. Major,
// minor and patch are zero-padded, then a flag digit ('0' prerelease present,
// '1' not) puts 1.0.0-rc.1 before 1.0.0, followed by one kind+payload pair per
// prerelease identifier (numeric identifiers sort first). Build metadata is
// dropped since semver says it doesn't affect precedence.
func SemverSort(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("semver sort %q: empty", raw)
	}

	// Masterminds treats major.minor and major alone as valid, defaulting the
	// missing parts to zero; this format requires all three explicitly.
	core := strings.TrimPrefix(trimmed, "v")
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	if n := strings.Count(core, ".") + 1; n != 3 {
		return "", fmt.Errorf("semver sort %q: want major.minor.patch, got %d parts", raw, n)
	}

	// StrictNewVersion, not NewVersion: the package's own NewVersion coerces a
	// leading zero (CoerceNewVersion defaults true), which this format forbids.
	version, err := semver.StrictNewVersion(strings.TrimPrefix(trimmed, "v"))
	if err != nil {
		return "", fmt.Errorf("semver sort %q: %w", raw, err)
	}

	var key strings.Builder
	for _, n := range [3]uint64{version.Major(), version.Minor(), version.Patch()} {
		padded, padErr := paddedNumber(strconv.FormatUint(n, 10), semverSortNumberWidth)
		if padErr != nil {
			return "", fmt.Errorf("semver sort %q: %w", raw, padErr)
		}
		key.WriteString(padded)
	}

	pre := version.Prerelease()
	if pre == "" {
		key.WriteByte('1')
		return key.String(), nil
	}
	key.WriteByte('0')

	for _, ident := range strings.Split(pre, ".") {
		if isNumericIdent(ident) {
			padded, padErr := paddedNumber(ident, semverSortIdentWidth)
			if padErr != nil {
				return "", fmt.Errorf("semver sort %q: %w", raw, padErr)
			}
			key.WriteByte('0')
			key.WriteString(padded)
			continue
		}
		if len(ident) > semverSortIdentWidth {
			return "", fmt.Errorf("semver sort %q: prerelease identifier %q is longer than %d", raw, ident, semverSortIdentWidth)
		}
		key.WriteByte('1')
		key.WriteString(ident)
		key.WriteString(strings.Repeat(semverSortPad, semverSortIdentWidth-len(ident)))
	}

	return key.String(), nil
}

func paddedNumber(s string, width int) (string, error) {
	if len(s) > width {
		return "", fmt.Errorf("%q has more than %d digits", s, width)
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

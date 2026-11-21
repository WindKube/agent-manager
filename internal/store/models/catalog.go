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

// Publisher owns packages. `verified` is set by a catalog admin, never
// inferred from the slug prefix.
type Publisher struct {
	bun.BaseModel `bun:"table:publisher,alias:pub"`

	ID uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	// Slug is the whole owner, e.g. `example` or `example/platform`.
	Slug        string    `bun:"slug,type:text,notnull,unique"`
	DisplayName string    `bun:"display_name,type:text,notnull"`
	Verified    bool      `bun:"verified,type:boolean,notnull,default:false"`
	CreatedAt   time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt   time.Time `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Packages []*Package `bun:"rel:has-many,join:id=publisher_id"`
}

// Category is admin-curated, unlike a version's free-form tags.
type Category struct {
	bun.BaseModel `bun:"table:category,alias:cat"`

	ID        uuid.UUID `bun:"id,pk,type:uuid,notnull"`
	Name      string    `bun:"name,type:text,notnull,unique"`
	Slug      string    `bun:"slug,type:text,notnull,unique"`
	CreatedAt time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt time.Time `bun:"updated_at,type:timestamptz,notnull,default:now()"`
}

// Package is the named unit a publisher owns. It is unique on `(namespace,
// name)` so two publishers cannot resolve to the same object key.
type Package struct {
	bun.BaseModel `bun:"table:package,alias:pkg"`

	ID          uuid.UUID         `bun:"id,pk,type:uuid,notnull"`
	PublisherID uuid.UUID         `bun:"publisher_id,type:uuid,notnull"`
	Namespace   string            `bun:"namespace,type:text,notnull,unique:package_namespace_name"`
	Name        string            `bun:"name,type:text,notnull,unique:package_namespace_name"`
	Kind        PackageKind       `bun:"kind,type:package_kind,notnull"`
	CategoryID  *uuid.UUID        `bun:"category_id,type:uuid,nullzero"`
	Visibility  PackageVisibility `bun:"visibility,type:package_visibility,notnull"`
	// OwnerIdentityID is who first registered the package and is never
	// reassigned. Null means "no owner", not "everyone's".
	OwnerIdentityID *uuid.UUID `bun:"owner_identity_id,type:uuid,nullzero"`
	// ParentPackageID is set when a skill is distributed inside a plugin.
	ParentPackageID *uuid.UUID `bun:"parent_package_id,type:uuid,nullzero"`
	LatestVersionID *uuid.UUID `bun:"latest_version_id,type:uuid,nullzero"`
	// Source of the last registration. SourceURL is the canonical repo for git,
	// the requested URL for an archive, null for an upload.
	SourceKind         FetchSourceKind `bun:"source_kind,type:fetch_source_kind,nullzero"`
	SourceURL          string          `bun:"source_url,type:text,nullzero"`
	SourceRef          string          `bun:"source_ref,type:text,nullzero"`
	SourceSubdirectory string          `bun:"source_subdirectory,type:text,nullzero"`
	// TrackUpstream opts a git package into periodic registration of new tags
	// matching TagPattern (a path.Match glob).
	TrackUpstream  bool       `bun:"track_upstream,type:boolean,notnull,default:false"`
	TagPattern     string     `bun:"tag_pattern,type:text,notnull,default:'v*'"`
	LastCheckedAt  *time.Time `bun:"last_checked_at,type:timestamptz,nullzero"`
	LastCheckError string     `bun:"last_check_error,type:text,nullzero"`
	// ExpectedSignerIssuer (exact) and ExpectedSignerIdentity (whole-match RE2)
	// constrain a version's verified Sigstore signer.
	ExpectedSignerIssuer   string    `bun:"expected_signer_issuer,type:text,nullzero"`
	ExpectedSignerIdentity string    `bun:"expected_signer_identity,type:text,nullzero"`
	CreatedAt              time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt              time.Time `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Publisher *Publisher `bun:"rel:belongs-to,join:publisher_id=id"`
	Category  *Category  `bun:"rel:belongs-to,join:category_id=id"`
	Owner     *Identity  `bun:"rel:belongs-to,join:owner_identity_id=id"`
	Parent    *Package   `bun:"rel:belongs-to,join:parent_package_id=id"`
	Versions  []*Version `bun:"rel:has-many,join:id=package_id"`
}

// Version is append-only: bytes, digest and manifest for one immutable release.
type Version struct {
	bun.BaseModel `bun:"table:version,alias:ver"`

	ID         uuid.UUID       `bun:"id,pk,type:uuid,notnull"`
	PackageID  uuid.UUID       `bun:"package_id,type:uuid,notnull,unique:version_package_semver"`
	Semver     string          `bun:"semver,type:text,notnull,unique:version_package_semver"`
	SemverSort string          `bun:"semver_sort,type:text,notnull"`
	ObjectKey  string          `bun:"object_key,type:text,notnull"`
	Digest     []byte          `bun:"digest,type:bytea,nullzero"`
	SizeBytes  *int64          `bun:"size_bytes,type:bigint,nullzero"`
	Manifest   json.RawMessage `bun:"manifest,type:jsonb,notnull"`
	Tags       []string        `bun:"tags,array,type:text[],notnull,default:'{}'"`
	DistTag    DistTag         `bun:"dist_tag,type:dist_tag,notnull"`
	Verdict    Verdict         `bun:"verdict,type:verdict,notnull"`
	// Visible is flipped last, once bytes, digest and metadata have all landed.
	Visible bool `bun:"visible,type:boolean,notnull,default:false"`
	// SourceURL is where the bytes came from: the canonical repo for git, the
	// post-redirect URL (no userinfo or query) for an archive, null for an upload.
	SourceURL    string    `bun:"source_url,type:text,nullzero"`
	SourceRef    string    `bun:"source_ref,type:text,nullzero"`
	SourceCommit string    `bun:"source_commit,type:text,nullzero"`
	CreatedAt    time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Package      *Package      `bun:"rel:belongs-to,join:package_id=id"`
	VersionTags  []*VersionTag `bun:"rel:has-many,join:id=version_id"`
	Components   []*Component  `bun:"rel:has-many,join:id=version_id"`
	Capabilities []*Capability `bun:"rel:has-many,join:id=version_id"`
	Signature    *Signature    `bun:"rel:has-one,join:id=version_id"`
}

// VersionTag holds the free-form keywords read from the manifest.
type VersionTag struct {
	bun.BaseModel `bun:"table:version_tag,alias:vtag"`

	VersionID uuid.UUID `bun:"version_id,pk,type:uuid,notnull"`
	Tag       string    `bun:"tag,pk,type:text,notnull"`
	CreatedAt time.Time `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Version *Version `bun:"rel:belongs-to,join:version_id=id"`
}

// Component is derived from the bundle's file tree, not the manifest.
type Component struct {
	bun.BaseModel `bun:"table:component,alias:cmp"`

	VersionID uuid.UUID     `bun:"version_id,pk,type:uuid,notnull"`
	Path      string        `bun:"path,pk,type:text,notnull"`
	Kind      ComponentKind `bun:"kind,type:component_kind,notnull"`
	Name      string        `bun:"name,type:text,notnull"`
	Note      string        `bun:"note,type:text,nullzero"`
	Event     string        `bun:"event,type:text,nullzero"`
	Matcher   string        `bun:"matcher,type:text,nullzero"`
	Transport string        `bun:"transport,type:text,nullzero"`
	Target    string        `bun:"target,type:text,nullzero"`
	CreatedAt time.Time     `bun:"created_at,type:timestamptz,notnull,default:now()"`

	Version *Version `bun:"rel:belongs-to,join:version_id=id"`
}

// Capability records what a version can reach, keyed by source: `inferred`
// from the scanner, `expected` from the manifest.
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

// Signature is registry-side metadata, never a manifest field. Kind none with
// a null Result means unsigned.
type Signature struct {
	bun.BaseModel `bun:"table:signature,alias:sig"`

	VersionID  uuid.UUID        `bun:"version_id,pk,type:uuid,notnull"`
	Ref        string           `bun:"ref,type:text,nullzero"`
	Kind       SignatureKind    `bun:"kind,type:signature_kind,notnull"`
	VerifiedAt *time.Time       `bun:"verified_at,type:timestamptz,nullzero"`
	VerifiedBy string           `bun:"verified_by,type:text,nullzero"`
	Result     *SignatureResult `bun:"result,type:signature_result,nullzero"`
	// Bundle is null when what was found was not JSON.
	Bundle json.RawMessage `bun:"bundle,type:jsonb,nullzero"`
	// ArtifactDigest is the sha256 of the archive as downloaded, which the bundle
	// was checked against; the stored object is a repack.
	ArtifactDigest []byte `bun:"artifact_digest,type:bytea,nullzero"`
	// SignerIssuer and SignerIdentity are set only on a verified row.
	SignerIssuer   string     `bun:"signer_issuer,type:text,nullzero"`
	SignerIdentity string     `bun:"signer_identity,type:text,nullzero"`
	SignedAt       *time.Time `bun:"signed_at,type:timestamptz,nullzero"`
	LogIndex       *int64     `bun:"log_index,type:bigint,nullzero"`
	Reason         string     `bun:"reason,type:text,nullzero"`
	CreatedAt      time.Time  `bun:"created_at,type:timestamptz,notnull,default:now()"`
	UpdatedAt      time.Time  `bun:"updated_at,type:timestamptz,notnull,default:now()"`

	Version *Version `bun:"rel:belongs-to,join:version_id=id"`
}

const semverSortNumberWidth = 10

const semverSortIdentWidth = 20

// semverSortPad is the lowest character semver allows in an identifier, so a
// short identifier sorts before a longer one sharing its prefix.
const semverSortPad = "-"

// SemverSort computes version.semver_sort: a key whose byte order is semver's
// precedence order, so `order by semver_sort desc` is an index scan.
func SemverSort(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("semver sort %q: empty", raw)
	}

	core := strings.TrimPrefix(trimmed, "v")
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	if n := strings.Count(core, ".") + 1; n != 3 {
		return "", fmt.Errorf("semver sort %q: want major.minor.patch, got %d parts", raw, n)
	}

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

package seed

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"agent-manager/internal/domain/capability"
	"agent-manager/internal/store/models"
)

// The rows half of the seed. One transaction: either the dataset is there or it
// is not, and a half-loaded catalog is not a state any screen should have to
// render.
//
// IDENTIFIERS ARE DERIVED, not generated. Every id below is uuid v5 over the
// row's natural key, so a re-run computes the same id, every insert can carry
// `on conflict do nothing`, and no step has to read back what the step before it
// wrote. That is what makes the one-shot safe to repeat (the compose service may
// run on every `up`) and it also makes a partially-applied run self-heal: the
// rows that landed are skipped and the rest are written, with the cross-references
// still agreeing.
//
// `category` is the one exception, and the reason is worth knowing before
// changing it: the category facet recovers the admin-curated order from the row
// ids, which only works because they are uuid v7 and sort by creation. A derived
// id would order the vocabulary arbitrarily, so those rows keep generated ids and
// are read back.
//
// Nothing is updated and nothing is deleted. A dataset change therefore needs a
// fresh database rather than a re-run — the seed fills an empty schema, it does
// not reconcile one.

// idNamespace anchors the derived ids. It is arbitrary and must never change: it
// is what makes "the same row" mean the same uuid across runs and machines.
var idNamespace = uuid.MustParse("9f1a6f5e-3c2b-4d7a-8e11-6a0c5f2d4b83")

func seedID(kind, key string) uuid.UUID {
	return uuid.NewSHA1(idNamespace, []byte(kind+"\x00"+key))
}

// index is the built dataset addressed the way the row writers need it.
type index struct {
	byRef  map[string]*builtVersion
	latest map[string]*builtVersion
}

func newIndex(built []*builtVersion) (index, error) {
	idx := index{
		byRef:  make(map[string]*builtVersion, len(built)),
		latest: make(map[string]*builtVersion, len(built)),
	}
	for _, version := range built {
		idx.byRef[version.ref.String()] = version
		if version.spec.distTag == models.DistTagLatest {
			if previous, dup := idx.latest[version.id()]; dup {
				return index{}, fmt.Errorf("%s and %s both claim the latest tag",
					previous.ref, version.ref)
			}
			idx.latest[version.id()] = version
		}
	}
	for _, version := range built {
		if _, ok := idx.latest[version.id()]; !ok {
			return index{}, fmt.Errorf("%s has no version tagged latest", version.id())
		}
	}
	return idx, nil
}

func writeRows(
	ctx context.Context,
	db bun.IDB,
	built []*builtVersion,
	idx index,
	revisionRows []models.Revision,
	now time.Time,
) error {
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		insert := func(what string, model any) error {
			if _, err := tx.NewInsert().Model(model).On("conflict do nothing").Exec(ctx); err != nil {
				return fmt.Errorf("seed %s: %w", what, err)
			}
			return nil
		}

		categoryIDs, err := writeCategories(ctx, tx)
		if err != nil {
			return err
		}
		if err := writeCatalog(ctx, tx, insert, built, idx, categoryIDs, now); err != nil {
			return err
		}
		if err := writeGovernance(insert, now); err != nil {
			return err
		}
		if err := writeScans(insert, built, idx, now); err != nil {
			return err
		}
		if err := writeProfiles(insert, idx, revisionRows, now); err != nil {
			return err
		}
		return writeAudit(insert, len(built), now)
	})
}

// writeCategories inserts the vocabulary in curated order and reads the ids back.
// See the note at the top of this file for why these ids are generated.
func writeCategories(ctx context.Context, tx bun.Tx) (map[string]uuid.UUID, error) {
	rows := make([]models.Category, 0, len(categories))
	for _, name := range categories {
		rows = append(rows, models.Category{ID: models.NewID(), Name: name, Slug: categorySlug(name)})
	}
	if _, err := tx.NewInsert().Model(&rows).On("conflict do nothing").Exec(ctx); err != nil {
		return nil, fmt.Errorf("seed categories: %w", err)
	}

	var stored []models.Category
	if err := tx.NewSelect().Model(&stored).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read back the categories: %w", err)
	}
	out := make(map[string]uuid.UUID, len(stored))
	for _, row := range stored {
		out[row.Name] = row.ID
	}
	for _, name := range categories {
		if _, ok := out[name]; !ok {
			return nil, fmt.Errorf("category %q is missing after insert", name)
		}
	}
	return out, nil
}

func categorySlug(name string) string {
	return strings.ToLower(strings.NewReplacer(" & ", "-", " ", "-").Replace(name))
}

func writeCatalog(
	ctx context.Context,
	tx bun.Tx,
	insert func(string, any) error,
	built []*builtVersion,
	idx index,
	categoryIDs map[string]uuid.UUID,
	now time.Time,
) error {
	publisherRows := make([]models.Publisher, 0, len(publishers))
	for _, spec := range publishers {
		publisherRows = append(publisherRows, models.Publisher{
			ID: seedID("publisher", spec.slug), Slug: spec.slug,
			DisplayName: spec.display, Verified: spec.verified,
		})
	}
	if err := insert("publishers", &publisherRows); err != nil {
		return err
	}

	packageRows := make([]models.Package, 0, len(designPackages))
	for i := range designPackages {
		spec := &designPackages[i]
		categoryID := categoryIDs[spec.category]
		row := models.Package{
			ID:          seedID("package", spec.id()),
			PublisherID: seedID("publisher", spec.publisher),
			// Held to the publisher's own first segment by a composite foreign key, so
			// this cannot name a namespace the publisher does not belong to.
			Namespace:  namespaceOf(spec.publisher),
			Name:       spec.name,
			Kind:       spec.kind,
			CategoryID: &categoryID,
			Visibility: models.PackageVisibilityOrganisation,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if spec.parent != "" {
			parent := seedID("package", spec.parent)
			row.ParentPackageID = &parent
		}
		packageRows = append(packageRows, row)
	}
	if err := insert("packages", &packageRows); err != nil {
		return err
	}

	versionRows := make([]models.Version, 0, len(built))
	var (
		tagRows       []models.VersionTag
		componentRows []models.Component
		signatureRows []models.Signature
	)
	for _, version := range built {
		sortKey, err := models.SemverSort(version.ref.Semver)
		if err != nil {
			return fmt.Errorf("seed %s: %w", version.ref, err)
		}
		digest := version.digest
		size := version.size
		createdAt := now.Add(-version.spec.age)
		tags := versionTags(version.pkg.keywords)

		versionRows = append(versionRows, models.Version{
			ID:         seedID("version", version.ref.String()),
			PackageID:  seedID("package", version.id()),
			Semver:     version.ref.Semver,
			SemverSort: sortKey,
			ObjectKey:  version.ref.BundleKey(),
			Digest:     digest[:],
			SizeBytes:  &size,
			Manifest:   version.inspected.ManifestJSON,
			Tags:       tags,
			DistTag:    version.spec.distTag,
			Verdict:    version.spec.verdict,
			Visible:    true,
			CreatedAt:  createdAt,
		})

		versionID := seedID("version", version.ref.String())
		for _, tag := range tags {
			tagRows = append(tagRows, models.VersionTag{VersionID: versionID, Tag: tag, CreatedAt: createdAt})
		}
		for _, component := range version.inspected.Components {
			kind := models.ComponentKind(component.Kind)
			if !kind.Valid() {
				return fmt.Errorf("seed %s: component kind %q", version.ref, component.Kind)
			}
			componentRows = append(componentRows, models.Component{
				VersionID: versionID, Path: component.Path, Kind: kind,
				Name: component.Name, Note: component.Note, CreatedAt: createdAt,
			})
		}
		// Kind `none` states that no signature was supplied, which is a row the
		// screens can read rather than a missing row they have to interpret (001
		// FR-048a, R9).
		signatureRows = append(signatureRows, models.Signature{
			VersionID: versionID, Kind: models.SignatureKindNone,
			CreatedAt: createdAt, UpdatedAt: createdAt,
		})
	}
	if err := insert("versions", &versionRows); err != nil {
		return err
	}
	if err := insert("version tags", &tagRows); err != nil {
		return err
	}
	if err := insert("components", &componentRows); err != nil {
		return err
	}
	if err := insert("signatures", &signatureRows); err != nil {
		return err
	}

	capabilityRows, err := capabilities(built, now)
	if err != nil {
		return err
	}
	if err := insert("capabilities", &capabilityRows); err != nil {
		return err
	}

	// The pointer comes last: a package is invisible to the catalog until it names
	// a visible version, so this is the seed's own commit-last step. It is an
	// update rather than a column on the insert above because the foreign key runs
	// the other way — the version row has to exist first.
	for id, version := range idx.latest {
		if _, err := tx.NewUpdate().Model((*models.Package)(nil)).
			Set("latest_version_id = ?", seedID("version", version.ref.String())).
			Set("updated_at = ?", now).
			Where("id = ? and latest_version_id is null", seedID("package", id)).
			Exec(ctx); err != nil {
			return fmt.Errorf("point %s at its latest version: %w", id, err)
		}
	}
	return nil
}

// versionTags is the fetcher's rule, restated because the seed must produce the
// same shape it does: version.tags is version_tag denormalised for the catalog's
// GIN index, so both are sorted and deduplicated.
func versionTags(keywords []string) []string {
	out := make([]string, 0, len(keywords))
	for _, tag := range keywords {
		if tag != "" && !slices.Contains(out, tag) {
			out = append(out, tag)
		}
	}
	slices.Sort(out)
	return out
}

// capabilities writes both sides of FR-027's comparison.
//
// The `expected` rows are READ BACK out of the stored manifest by
// capability.Expected rather than written from the dataset, so the panel cannot
// show a declaration the manifest does not carry. The `inferred` rows are the
// scanner's output and the seed stands in for it until the scanner worker is
// registered; a version whose scan has not finished gets rows of neither source,
// which is the state the panel must render as "not scanned yet".
func capabilities(built []*builtVersion, now time.Time) ([]models.Capability, error) {
	rows := make([]models.Capability, 0, len(built)*3)
	for _, version := range built {
		if !version.spec.scanned {
			continue
		}
		versionID := seedID("version", version.ref.String())
		createdAt := now.Add(-version.spec.age)

		declared, err := capability.Expected(version.inspected.ManifestJSON)
		if err != nil {
			return nil, fmt.Errorf("read the expected capabilities of %s: %w", version.ref, err)
		}
		for _, entry := range declared {
			row, err := capabilityRow(versionID, models.CapabilitySourceExpected,
				entry.Name, string(entry.Level), entry.Detail, entry.Indefinite, createdAt)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", version.ref, err)
			}
			rows = append(rows, row)
		}
		for _, entry := range version.pkg.inferred {
			row, err := capabilityRow(versionID, models.CapabilitySourceInferred,
				entry.name, entry.level, entry.detail, entry.indefinite, createdAt)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", version.ref, err)
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func capabilityRow(
	versionID uuid.UUID,
	source models.CapabilitySource,
	name, level string,
	detail []string,
	indefinite bool,
	at time.Time,
) (models.Capability, error) {
	// FR-018's floor, applied to both sources for the same reason the domain
	// applies it: a level is a claim about how much trust the capability demands,
	// not about who wrote it down, and an indefinite target set is not a list a
	// reviewer can accept once.
	if name == capability.Shell || indefinite {
		level = string(capability.LevelReview)
	}
	stored := models.CapabilityLevel(level)
	if !stored.Valid() {
		return models.Capability{}, fmt.Errorf("capability %q has level %q", name, level)
	}
	targets := detail
	if targets == nil {
		targets = []string{}
	}
	encoded, err := json.Marshal(struct {
		Targets    []string `json:"targets"`
		Indefinite bool     `json:"indefinite"`
	}{Targets: targets, Indefinite: indefinite})
	if err != nil {
		return models.Capability{}, err
	}
	return models.Capability{
		VersionID: versionID, Source: source, Name: name,
		Detail: encoded, Level: stored, CreatedAt: at,
	}, nil
}

func writeGovernance(insert func(string, any) error, now time.Time) error {
	identityRows := make([]models.Identity, 0, len(identities))
	for _, spec := range identities {
		seen := now.Add(-3 * time.Hour)
		identityRows = append(identityRows, models.Identity{
			ID: seedID("identity", spec.subject), Subject: spec.subject, Email: spec.email,
			DisplayName: spec.display, Groups: spec.groups, LastSeenAt: &seen,
			CreatedAt: now, UpdatedAt: now,
		})
	}
	if err := insert("identities", &identityRows); err != nil {
		return err
	}

	roleRows := make([]models.GroupRoleMap, 0, len(GroupRoles))
	for _, mapping := range GroupRoles {
		roleRows = append(roleRows, models.GroupRoleMap{
			GroupName: mapping.Group, Role: mapping.Role, CreatedAt: now, UpdatedAt: now,
		})
	}
	if err := insert("the group-to-role map", &roleRows); err != nil {
		return err
	}

	row := policy
	row.CreatedAt = now
	row.UpdatedAt = now
	return insert("the org policy", &row)
}

func writeScans(
	insert func(string, any) error,
	built []*builtVersion,
	idx index,
	now time.Time,
) error {
	deviations := map[string][]checkSpec{}
	for i := range designFindings {
		finding := &designFindings[i]
		deviations[finding.pkg+"@"+finding.semver] = finding.checks
	}

	var (
		scanRows  []models.Scan
		checkRows []models.ScanCheck
	)
	for i, version := range built {
		ref := version.ref.String()
		scanID := seedID("scan", ref)
		createdAt := now.Add(-version.spec.age)
		started := createdAt.Add(12 * time.Second)

		if !version.spec.scanned {
			// In flight. `finished_at is null` is what makes the detail page say the
			// version has not been scanned, and it is the design's "Scan pending"
			// badge as a row rather than as a rendering rule.
			scanRows = append(scanRows, models.Scan{
				ID: scanID, VersionID: seedID("version", ref), PackVersion: packVersion,
				StartedAt: now.Add(-90 * time.Second), Verdict: models.VerdictScanning,
				UpdatedAt: now,
			})
			continue
		}

		finished := started.Add(scanDuration(i))
		scanRows = append(scanRows, models.Scan{
			ID: scanID, VersionID: seedID("version", ref), PackVersion: packVersion,
			StartedAt: started, FinishedAt: &finished, Verdict: version.spec.verdict,
			UpdatedAt: finished,
		})

		results := map[string]checkSpec{}
		for _, deviation := range deviations[ref] {
			results[deviation.id] = deviation
		}
		for _, check := range standardChecks {
			row := models.ScanCheck{
				ScanID: scanID, CheckID: check.id, Label: check.label,
				Result: models.CheckResultPass, CreatedAt: finished,
			}
			if deviation, ok := results[check.id]; ok {
				row.Result = deviation.result
				row.WarnCount = deviation.warns
			}
			checkRows = append(checkRows, row)
		}
	}
	if err := insert("scans", &scanRows); err != nil {
		return err
	}
	if err := insert("scan checks", &checkRows); err != nil {
		return err
	}

	findingRows := make([]models.Finding, 0, len(designFindings))
	var overrideRows []models.Override
	for i := range designFindings {
		spec := &designFindings[i]
		ref := spec.pkg + "@" + spec.semver
		version, ok := idx.byRef[ref]
		if !ok {
			return fmt.Errorf("finding %s names %s, which the dataset does not seed", spec.rule, ref)
		}
		path, line, quote, err := version.locate(spec.rule)
		if err != nil {
			return err
		}
		raised := findingRaisedAt(version, now)
		decided := findingDecidedAt(spec, version, now)

		findingRows = append(findingRows, models.Finding{
			ID: seedID("finding", spec.rule), ScanID: seedID("scan", ref),
			VersionID: seedID("version", ref), RuleID: spec.rule, Severity: spec.severity,
			Title: spec.title, Detail: spec.detail,
			EvidencePath: path, EvidenceLine: &line, EvidenceQuote: quote,
			State: spec.state, CreatedAt: raised, UpdatedAt: decided,
		})

		if spec.override == nil {
			continue
		}
		reviewer, ok := identityBy(spec.override.reviewer)
		if !ok {
			return fmt.Errorf("finding %s is overridden by %s, who is not a seeded identity",
				spec.rule, spec.override.reviewer)
		}
		expires := decided.Add(spec.override.expiresIn)
		overrideRows = append(overrideRows, models.Override{
			FindingID: seedID("finding", spec.rule), ReviewerIdentityID: reviewer,
			Note: spec.override.note, ExpiresAt: &expires, CreatedAt: decided,
		})
	}
	if err := insert("findings", &findingRows); err != nil {
		return err
	}
	return insert("overrides", &overrideRows)
}

// findingFor is the seeded finding against one version, addressed as
// publisher/name@semver, or nil where the dataset raised none.
func findingFor(ref string) *findingSpec {
	for i := range designFindings {
		if designFindings[i].pkg+"@"+designFindings[i].semver == ref {
			return &designFindings[i]
		}
	}
	return nil
}

// findingRaisedAt and findingDecidedAt are the two instants a seeded finding
// carries. They are functions rather than arithmetic inlined at the one call site
// because profile resolution reads the acceptance expiry these produce, and two
// spellings of "when was this decided" is two answers to when an override lapses.
func findingRaisedAt(version *builtVersion, now time.Time) time.Time {
	return now.Add(-version.spec.age).Add(time.Minute)
}

func findingDecidedAt(spec *findingSpec, version *builtVersion, now time.Time) time.Time {
	if spec.state == models.FindingStateOpen {
		return findingRaisedAt(version, now)
	}
	return now.Add(-3 * time.Hour)
}

// scanDuration spreads the seeded scans around the design's 18 s median so the
// scanner screen's median figure is computed from rows rather than displayed from
// a constant.
func scanDuration(i int) time.Duration {
	return time.Duration(18+3*(i%5-2)) * time.Second
}

func identityBy(email string) (uuid.UUID, bool) {
	for _, spec := range identities {
		if spec.email == email {
			return seedID("identity", spec.subject), true
		}
	}
	return uuid.UUID{}, false
}

func writeAudit(insert func(string, any) error, versions int, now time.Time) error {
	// audit_event is append-only by revoked grant (FR-052): no update, no delete,
	// no truncate, for any role. So the idempotence of these rows cannot come from
	// an upsert — it comes from the derived id and `on conflict do nothing`, which
	// is the one shape the grants permit.
	rows := make([]models.AuditEvent, 0, 8)
	for _, spec := range auditRows(versions) {
		rows = append(rows, models.AuditEvent{
			ID:         seedID("audit", spec.text),
			OccurredAt: now.Add(-spec.ago),
			Actor:      spec.actor,
			ActorKind:  spec.actorKind,
			Kind:       spec.kind,
			Text:       spec.text,
			Source:     spec.source,
		})
	}
	return insert("audit events", &rows)
}

// locate reads a finding's evidence off the bytes the seed just packed. The
// dataset states the offending line; the path, the line number and the quote come
// from the stored tree, so evidence cannot point at a line the bundle does not
// contain.
func (b *builtVersion) locate(rule string) (path string, line int32, quote string, err error) {
	flaw := b.pkg.flaw
	if flaw == nil || !flaw.carriedBy(b.ref.Semver) {
		return "", 0, "", fmt.Errorf("finding %s has no seeded evidence in %s", rule, b.ref)
	}
	file, ok := b.inspected.Files.Lookup(flaw.path)
	if !ok {
		return "", 0, "", fmt.Errorf("finding %s: %s holds no %s", rule, b.ref, flaw.path)
	}
	for i, text := range strings.Split(string(file.Data), "\n") {
		if strings.Contains(text, flaw.line) {
			return flaw.path, int32(i + 1), strings.TrimSpace(text), nil
		}
	}
	return "", 0, "", fmt.Errorf("finding %s: %s does not contain the quoted line", rule, flaw.path)
}

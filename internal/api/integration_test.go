//go:build integration

// The api role against a real Postgres.
//
// Everything asserted here is a guarantee the code cannot make on its own: that
// the FR-044 predicate is SQL and not a Go filter, that a session row yields no
// usable credential, that a command's audit row commits with its mutation, and
// that a group with no mapping grants nothing. A handler-shaped test with a fake
// store would pass against every one of those being broken.
package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"agent-manager/internal/api"
	"agent-manager/internal/api/commands"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/api/queries"
	"agent-manager/internal/auth"
	"agent-manager/internal/blob"
	"agent-manager/internal/store/migrations"
	"agent-manager/internal/store/models"
)

var (
	pool     *pgxpool.Pool
	db       *bun.DB
	recorder *statements
	appURL   string
	queueURL string

	bundleKey   = "skills/acme/code-review/2.4.1/bundle.tar.zst"
	bundleBytes = []byte("not really zstd, but immutable bytes with a digest")
	bundleSHA   = bytes.Repeat([]byte{0xab}, 32)

	// A second team publishing into the SAME namespace. Both packages are reached
	// through the same first path segment, which is what makes the segment a
	// namespace rather than a publisher.
	siblingKey   = "skills/acme/threat-model/1.0.0/bundle.tar.zst"
	siblingBytes = []byte("a different team's bytes, under the same namespace")
	siblingSHA   = bytes.Repeat([]byte{0xcd}, 32)
)

// statements records every statement bun sends. It is how the FR-044 test proves
// the filtering is in SQL: a fetch-then-filter implementation either issues more
// statements than one, or issues one that returns more rows than it returns.
type statements struct {
	mu      sync.Mutex
	enabled bool
	seen    []string
}

func (s *statements) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enabled {
		s.seen = append(s.seen, event.Query)
	}
	return ctx
}

func (s *statements) AfterQuery(context.Context, *bun.QueryEvent) {}

func (s *statements) record() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled, s.seen = true, nil
}

func (s *statements) stop() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = false
	return s.seen
}

func TestMain(m *testing.M) {
	code, err := runSuite(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "api integration suite:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runSuite(m *testing.M) (int, error) {
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("agent_manager"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return 0, fmt.Errorf("start postgres: %w", err)
	}
	defer func() {
		if termErr := container.Terminate(ctx); termErr != nil {
			fmt.Fprintln(os.Stderr, "terminate postgres:", termErr)
		}
	}()

	endpoint, err := container.PortEndpoint(ctx, "5432/tcp", "")
	if err != nil {
		return 0, fmt.Errorf("container endpoint: %w", err)
	}
	appURL = fmt.Sprintf("postgres://postgres:postgres@%s/agent_manager?sslmode=disable", endpoint)
	queueURL = fmt.Sprintf("postgres://postgres:postgres@%s/river?sslmode=disable", endpoint)

	pool, err = pgxpool.New(ctx, appURL)
	if err != nil {
		return 0, fmt.Errorf("open pool: %w", err)
	}
	defer pool.Close()

	if _, err = pool.Exec(ctx, "create database river"); err != nil {
		return 0, fmt.Errorf("create queue database: %w", err)
	}

	// The checked-in migrations, not the desired state: what ships is the
	// migration directory, so that is what the api is tested against.
	if applyErr := migrations.Apply(ctx, func(ctx context.Context, statement string) error {
		_, execErr := pool.Exec(ctx, statement)
		return execErr
	}); applyErr != nil {
		return 0, applyErr
	}

	sqldb := stdlib.OpenDBFromPool(pool)
	defer func() { _ = sqldb.Close() }()

	recorder = &statements{}
	db = bun.NewDB(sqldb, pgdialect.New())
	db.RegisterModel(models.All()...)
	db.AddQueryHook(recorder)

	if seedErr := seed(ctx); seedErr != nil {
		return 0, seedErr
	}

	code := m.Run()
	// The boot test builds the binary once; ~40 MB of it does not need to outlive
	// the run.
	if binaryPath != "" {
		_ = os.Remove(binaryPath)
	}
	return code, nil
}

// ---- fixtures ---------------------------------------------------------------

type actor struct {
	claims auth.Claims
	token  string
}

var (
	// kw is in a mapped group and holds a direct membership on one private profile.
	kw actor
	// an is in a different mapped group, which is what makes the FR-044 test a
	// comparison of two identities rather than a check of one.
	an actor
	// contractor is in a group with NO mapping. It exists to prove that an
	// unmapped group grants nothing.
	contractor actor

	// curator, mate and punter exist for the profile write path and for nothing
	// else. They are separate people rather than reuses of kw and an because the
	// FR-044 assertions above compare those two identities' readable lists against
	// exact sets: a test that created a profile readable by kw would change the
	// answer to a question another test asks. Every profile they create is
	// `private` and shared only with each other, so no list in this file moves.
	curator actor
	mate    actor
	punter  actor
)

func seed(ctx context.Context) error {
	insert := func(model any) error {
		_, err := db.NewInsert().Model(model).Exec(ctx)
		return err
	}

	for _, mapping := range []*models.GroupRoleMap{
		{GroupName: "eng-platform", Role: models.OrgRoleCatalogAdmin},
		{GroupName: "eng-security", Role: models.OrgRoleScannerReviewer},
	} {
		if err := insert(mapping); err != nil {
			return fmt.Errorf("seed group_role_map: %w", err)
		}
	}

	// The singleton. Resolving a profile reads the gate out of it and there is no
	// default: a hub whose policy row is missing has no gate, and queries.ErrNoPolicy
	// refuses rather than guessing. `warn-with-override` is the value the
	// representative dataset ships, so the fixture starts where an operator does.
	// AllowPersonalProfiles is true here: most of this suite creates a profile
	// without stating a visibility, which defaults to private, and the fixture's
	// job is to exercise those tests' own feature rather than this toggle.
	// org_integration_test.go's own downstream test turns it off and back on.
	if err := insert(&models.OrgPolicy{
		ID:                    models.OrgPolicySingletonID,
		ScanGate:              models.ScanGateWarnWithOverride,
		DefaultVersionPolicy:  models.VersionPolicyFloatingLatest,
		AllowPersonalProfiles: true,
	}); err != nil {
		return fmt.Errorf("seed org_policy: %w", err)
	}

	profiles := map[string]*models.Profile{}
	for _, spec := range []struct {
		slug, name string
		visibility models.ProfileVisibility
	}{
		{"platform-baseline", "Platform baseline", models.ProfileVisibilityOrganisation},
		{"security-review", "Security review", models.ProfileVisibilityPrivate},
		{"kw-private", "Krzysztof's scratch profile", models.ProfileVisibilityPrivate},
		{"nobody-home", "Owned by somebody else entirely", models.ProfileVisibilityPrivate},
	} {
		profile := &models.Profile{
			ID:            models.NewID(),
			Slug:          spec.slug,
			Name:          spec.name,
			Visibility:    spec.visibility,
			DefaultPolicy: models.VersionPolicyFloatingLatest,
		}
		if err := insert(profile); err != nil {
			return fmt.Errorf("seed profile %s: %w", spec.slug, err)
		}
		profiles[spec.slug] = profile
	}

	for _, spec := range []struct {
		slug string
		kind models.SubjectKind
		ref  string
		role models.MembershipRole
	}{
		{"kw-private", models.SubjectKindUser, "kwiatrzyk@example.com", models.MembershipRoleOwner},
		{"security-review", models.SubjectKindGroup, "eng-security", models.MembershipRoleReviewer},
		{"nobody-home", models.SubjectKindUser, "somebody-else@example.com", models.MembershipRoleOwner},
	} {
		if err := insert(&models.Membership{
			ProfileID:   profiles[spec.slug].ID,
			SubjectKind: spec.kind,
			SubjectRef:  spec.ref,
			Role:        spec.role,
		}); err != nil {
			return fmt.Errorf("seed membership on %s: %w", spec.slug, err)
		}
	}

	for slug, seqs := range map[string][]int32{
		"platform-baseline": {1, 2},
		"security-review":   {1},
		"kw-private":        {1},
		"nobody-home":       {1},
	} {
		for _, seq := range seqs {
			lockfile, err := json.Marshal(lockfileFor(slug, int(seq)))
			if err != nil {
				return err
			}
			if err := insert(&models.Revision{
				ID:        models.NewID(),
				ProfileID: profiles[slug].ID,
				Seq:       seq,
				Note:      "seeded",
				Lockfile:  lockfile,
				ObjectKey: fmt.Sprintf("profiles/%s/r%d.json", slug, seq),
				CreatedBy: "seed",
			}); err != nil {
				return fmt.Errorf("seed revision %s r%d: %w", slug, seq, err)
			}
		}
	}

	// <namespace>/<team>: publisher.namespace is generated from the first segment
	// and package.namespace is held to it by a composite foreign key, so the two
	// cannot be seeded independently even here.
	publisher := &models.Publisher{ID: models.NewID(), Slug: "acme/platform", DisplayName: "Acme"}
	if err := insert(publisher); err != nil {
		return fmt.Errorf("seed publisher: %w", err)
	}
	pkg := &models.Package{
		ID:          models.NewID(),
		PublisherID: publisher.ID,
		Namespace:   "acme",
		Name:        "code-review",
		Kind:        models.PackageKindSkill,
		Visibility:  models.PackageVisibilityOrganisation,
	}
	if err := insert(pkg); err != nil {
		return fmt.Errorf("seed package: %w", err)
	}
	for _, spec := range []struct {
		semver  string
		verdict models.Verdict
		key     string
	}{
		{"2.4.1", models.VerdictClean, bundleKey},
		{"0.9.0", models.VerdictRejected, "skills/acme/code-review/0.9.0/bundle.tar.zst"},
	} {
		if err := insert(&models.Version{
			ID:         models.NewID(),
			PackageID:  pkg.ID,
			Semver:     spec.semver,
			SemverSort: spec.semver,
			ObjectKey:  spec.key,
			Digest:     bundleSHA,
			Manifest:   json.RawMessage(`{"name":"code-review"}`),
			Tags:       []string{"review"},
			DistTag:    models.DistTagLatest,
			Verdict:    spec.verdict,
			Visible:    true,
		}); err != nil {
			return fmt.Errorf("seed version %s: %w", spec.semver, err)
		}
	}

	// A sibling team in the same namespace. Its package is addressed through the
	// same `/v1/bundles/acme/...` prefix as the one above, which is the whole
	// point: the first path segment names the namespace and the publisher table
	// is not consulted at all.
	sibling := &models.Publisher{ID: models.NewID(), Slug: "acme/security", DisplayName: "Acme Security"}
	if err := insert(sibling); err != nil {
		return fmt.Errorf("seed sibling publisher: %w", err)
	}
	siblingPkg := &models.Package{
		ID:          models.NewID(),
		PublisherID: sibling.ID,
		Namespace:   "acme",
		Name:        "threat-model",
		Kind:        models.PackageKindSkill,
		Visibility:  models.PackageVisibilityOrganisation,
	}
	if err := insert(siblingPkg); err != nil {
		return fmt.Errorf("seed sibling package: %w", err)
	}
	if err := insert(&models.Version{
		ID:         models.NewID(),
		PackageID:  siblingPkg.ID,
		Semver:     "1.0.0",
		SemverSort: "1.0.0",
		ObjectKey:  siblingKey,
		Digest:     siblingSHA,
		Manifest:   json.RawMessage(`{"name":"threat-model"}`),
		Tags:       []string{"security"},
		DistTag:    models.DistTagLatest,
		Verdict:    models.VerdictClean,
		Visible:    true,
	}); err != nil {
		return fmt.Errorf("seed sibling version: %w", err)
	}

	// Sessions come from the real login command, so the fixtures exercise the
	// path a browser takes rather than a hand-written INSERT that could diverge
	// from it.
	for target, claims := range map[*actor]auth.Claims{
		&kw: {Subject: "sub-kw", Email: "kwiatrzyk@example.com", Name: "Krzysztof Wiatrzyk",
			Groups: []string{"eng-platform"}},
		&an: {Subject: "sub-an", Email: "anowak@example.com", Name: "Anna Nowak",
			Groups: []string{"eng-security"}},
		&contractor: {Subject: "sub-ct", Email: "contractor@example.com", Name: "A Contractor",
			Groups: []string{"contractors"}},
		&curator: {Subject: "sub-cu", Email: "curator@example.com", Name: "A Curator",
			Groups: []string{"eng-platform"}},
		&mate: {Subject: "sub-mt", Email: "mate@example.com", Name: "A Maintainer",
			Groups: []string{"eng-platform"}},
		&punter: {Subject: "sub-pu", Email: "punter@example.com", Name: "A Consumer",
			Groups: []string{"eng-platform"}},
	} {
		result, err := commands.Login(ctx, db, commands.LoginInput{
			Claims: claims, SessionTTL: time.Hour, Source: auth.SourceWeb,
		})
		if err != nil {
			return fmt.Errorf("seed session for %s: %w", claims.Subject, err)
		}
		target.claims, target.token = claims, result.Token
	}
	return nil
}

func lockfileFor(slug string, seq int) contract.Lockfile {
	return contract.Lockfile{
		SchemaVersion: "1.0.0",
		Profile:       contract.LockfileProfile{Slug: slug, Name: slug},
		Revision:      seq,
		ResolvedAt:    time.Now().UTC().Truncate(time.Second),
		Gate:          "approval",
		Entries: []contract.LockfileEntry{{
			ID: "acme/code-review", Kind: "skill", Version: "2.4.1",
			Digest:     "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			ObjectKey:  bundleKey,
			Resolution: "pinned", Verdict: "clean",
		}},
		Skipped: []contract.LockfileSkip{{
			ID: "acme/legacy-helper", Reason: "flagged-awaiting-approval",
			Detail: "SH-NET-002 in postinstall.sh",
		}},
		Targets: []string{"claude-code"},
	}
}

// liveHandler is the real router over the real database and a real (in-memory)
// bucket, so every test below goes through the middleware, the operation and the
// query exactly as a client would.
func liveHandler(t *testing.T) http.Handler {
	t.Helper()

	bucket, err := blob.Open(context.Background(), "mem://")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bucket.Close()) })
	for key, body := range map[string][]byte{bundleKey: bundleBytes, siblingKey: siblingBytes} {
		_, writeErr := bucket.Writer().Write(context.Background(), key, bytes.NewReader(body))
		require.NoError(t, writeErr)
	}

	return api.New(api.Deps{
		DB:       db,
		Bundles:  bucket.Reader(),
		Sessions: auth.NewSessions(db),
		Probes: []api.Probe{{Name: "database", Check: func(ctx context.Context) error {
			return pool.Ping(ctx)
		}}},
	}, api.Options{}).Handler()
}

func principalFor(t *testing.T, a actor) auth.Principal {
	t.Helper()

	principal, err := auth.NewSessions(db).Resolve(context.Background(), a.token)
	require.NoError(t, err)
	return principal
}

func slugsOf(profiles []contract.Profile) []string {
	out := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, profile.Slug)
	}
	return out
}

// ---- FR-044 ------------------------------------------------------------------

func TestListProfilesEnumeratesExactlyWhatTheIdentityMayRead(t *testing.T) {
	handler := liveHandler(t)

	for _, tc := range []struct {
		name  string
		who   *actor
		want  []string
		never string
	}{
		{
			name:  "a direct member sees the organisation profile and their own",
			who:   &kw,
			want:  []string{"kw-private", "platform-baseline"},
			never: "security-review",
		},
		{
			name:  "a group member sees the organisation profile and the group's",
			who:   &an,
			want:  []string{"platform-baseline", "security-review"},
			never: "kw-private",
		},
		{
			name:  "an identity whose group maps to nothing still sees organisation profiles",
			who:   &contractor,
			want:  []string{"platform-baseline"},
			never: "kw-private",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, handler, http.MethodGet, "/v1/profiles", tc.who.token, "")
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

			var body contract.ProfileList
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.ElementsMatch(t, tc.want, slugsOf(body.Profiles))
			require.NotContains(t, slugsOf(body.Profiles), tc.never)
			// The profile nobody is a member of is enumerated for nobody.
			require.NotContains(t, slugsOf(body.Profiles), "nobody-home")
		})
	}

	t.Run("two identities in different groups get different sets", func(t *testing.T) {
		a := listSlugs(t, handler, kw)
		b := listSlugs(t, handler, an)
		require.NotEqual(t, a, b, "FR-044 is not a filtered view of one shared list")
	})
}

func listSlugs(t *testing.T, handler http.Handler, who actor) []string {
	t.Helper()

	rec := request(t, handler, http.MethodGet, "/v1/profiles", who.token, "")
	require.Equal(t, http.StatusOK, rec.Code)
	var body contract.ProfileList
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return slugsOf(body.Profiles)
}

// The FR-044 wording is "a client sees exactly the profiles its identity may
// read, and no others" — not "a filtered view of a larger list". This is the test
// that tells the two implementations apart.
//
// Two independent sides: the statement the code actually sent (captured from
// bun's hook) is re-executed through pgx, and its row count must equal the number
// of profiles the handler returned. A fetch-then-filter implementation fails
// either the one-statement assertion or the row-count one.
func TestReadableProfilesFiltersInSQLRatherThanInGo(t *testing.T) {
	ctx := context.Background()
	principal := principalFor(t, kw)

	recorder.record()
	profiles, err := queries.ReadableProfiles(ctx, db, principal)
	sent := recorder.stop()
	require.NoError(t, err)
	require.Len(t, profiles, 2)

	require.Len(t, sent, 1, "listing readable profiles must be one statement, not one per profile:\n%v", sent)
	require.Contains(t, sent[0], "membership", "the readability predicate is not in the statement")

	rows, err := pool.Query(ctx, sent[0])
	require.NoError(t, err)
	defer rows.Close()

	returned := 0
	for rows.Next() {
		returned++
	}
	require.NoError(t, rows.Err())
	require.Equal(t, len(profiles), returned,
		"the statement returned %d rows and the handler returned %d: the difference was filtered in Go",
		returned, len(profiles))

	total := countRows(t, "select count(*) from profile")
	require.Greater(t, total, returned, "the fixture must contain a profile this identity cannot read")
}

// The negative control for FR-044: widen one identity's access and only that
// identity's list may change.
func TestGrantingAGroupAccessChangesOnlyThatIdentitysList(t *testing.T) {
	handler := liveHandler(t)
	ctx := context.Background()

	beforeKW := listSlugs(t, handler, kw)
	beforeAN := listSlugs(t, handler, an)
	require.NotContains(t, beforeAN, "kw-private")

	var profileID uuid.UUID
	require.NoError(t, pool.QueryRow(ctx, "select id from profile where slug = 'kw-private'").Scan(&profileID))
	_, err := pool.Exec(ctx,
		`insert into membership (profile_id, subject_kind, subject_ref, role)
		 values ($1, 'group', 'eng-security', 'consumer')`, profileID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := pool.Exec(ctx,
			`delete from membership where profile_id = $1 and subject_kind = 'group' and subject_ref = 'eng-security'`,
			profileID)
		require.NoError(t, cleanupErr)
	})

	afterAN, afterKW := listSlugs(t, handler, an), listSlugs(t, handler, kw)
	t.Logf("granted group eng-security consumer on kw-private")
	t.Logf("  anowak      before=%v after=%v", beforeAN, afterAN)
	t.Logf("  kwiatrzyk   before=%v after=%v", beforeKW, afterKW)

	require.ElementsMatch(t, append(beforeAN, "kw-private"), afterAN,
		"the identity whose group was granted access must now see the profile")
	require.ElementsMatch(t, beforeKW, afterKW,
		"no other identity's list may change")
	require.NotContains(t, listSlugs(t, handler, contractor), "kw-private")
}

// ---- the groups claim to role mapping ---------------------------------------

func TestGroupRoleMapIsTheOnlySourceOfARole(t *testing.T) {
	ctx := context.Background()

	require.Equal(t, models.OrgRoleCatalogAdmin, principalFor(t, kw).Role)
	require.Equal(t, models.OrgRoleScannerReviewer, principalFor(t, an).Role)

	t.Run("a group with no mapping grants nothing", func(t *testing.T) {
		principal := principalFor(t, contractor)
		require.Equal(t, []string{"contractors"}, principal.Groups,
			"the identity is in a group")
		require.Equal(t, models.OrgRole(""), principal.Role,
			"...and the group maps to nothing, so it grants nothing")
	})

	t.Run("removing a mapping removes the role", func(t *testing.T) {
		t.Logf("before: groups=%v role=%q", principalFor(t, kw).Groups, principalFor(t, kw).Role)
		_, err := pool.Exec(ctx, "delete from group_role_map where group_name = 'eng-platform'")
		require.NoError(t, err)
		t.Logf("after deleting eng-platform from group_role_map: groups=%v role=%q",
			principalFor(t, kw).Groups, principalFor(t, kw).Role)
		t.Cleanup(func() {
			_, restoreErr := pool.Exec(ctx,
				"insert into group_role_map (group_name, role) values ('eng-platform', 'catalog-admin')")
			require.NoError(t, restoreErr)
		})

		require.Equal(t, models.OrgRole(""), principalFor(t, kw).Role,
			"the role is derived per request from group_role_map, so unmapping the group takes it away")
	})
}

// ---- sessions ----------------------------------------------------------------

func TestSessionTokenIsHashedAtRestAndCannotBeReplayed(t *testing.T) {
	ctx := context.Background()

	result, err := commands.Login(ctx, db, commands.LoginInput{
		Claims:     auth.Claims{Subject: "sub-hash", Email: "hash@example.com", Groups: []string{"eng-platform"}},
		SessionTTL: time.Hour,
		Source:     auth.SourceWeb,
	})
	require.NoError(t, err)
	require.NotEmpty(t, result.Token)

	// Every column of the row, rendered as text. Not just token_hash: the point is
	// that the plaintext is nowhere in the row, not that one column holds a hash.
	var rendered string
	require.NoError(t, pool.QueryRow(ctx,
		`select to_jsonb(session)::text from session
		 where identity_id = $1`, result.IdentityID).Scan(&rendered))
	t.Logf("issued token:  %s", result.Token)
	t.Logf("stored row:    %s", rendered)
	require.NotContains(t, rendered, result.Token,
		"the raw token appears in the session row: a database read yields a bearer credential")

	var storedHash []byte
	require.NoError(t, pool.QueryRow(ctx,
		"select token_hash from session where identity_id = $1", result.IdentityID).Scan(&storedHash))
	require.Equal(t, auth.HashToken(result.Token), storedHash)

	sessions := auth.NewSessions(db)

	t.Run("the raw token resolves", func(t *testing.T) {
		principal, err := sessions.Resolve(ctx, result.Token)
		require.NoError(t, err)
		require.Equal(t, "sub-hash", principal.Subject)
		require.Equal(t, models.OrgRoleCatalogAdmin, principal.Role)
		require.Equal(t, auth.SourceWeb, principal.Source)
	})

	t.Run("the stored value cannot be replayed", func(t *testing.T) {
		for _, name := range []string{"raw bytes", "hex", "base64"} {
			replay := map[string]string{
				"raw bytes": string(storedHash),
				"hex":       fmt.Sprintf("%x", storedHash),
				"base64":    encodeBase64(storedHash),
			}[name]
			_, err := sessions.Resolve(ctx, replay)
			require.ErrorIsf(t, err, auth.ErrUnauthenticated,
				"the %s form of the stored hash was accepted as a bearer token", name)
		}
	})

	t.Run("an expired session does not resolve", func(t *testing.T) {
		require.NoError(t, commands.ExpireSession(ctx, db, result.Token))
		_, err := sessions.Resolve(ctx, result.Token)
		require.ErrorIs(t, err, auth.ErrUnauthenticated)

		// Expiry is an UPDATE, not a DELETE: no role holds DELETE on session.
		require.Equal(t, 1, countRows(t,
			fmt.Sprintf("select count(*) from session where identity_id = '%s'", result.IdentityID)))
	})

	t.Run("login wrote exactly one audit row inside its transaction", func(t *testing.T) {
		require.Equal(t, 1, countRows(t,
			"select count(*) from audit_event where kind = 'login' and actor = 'hash@example.com'"))
	})
}

// ---- commands ----------------------------------------------------------------

func TestReportSyncWritesOneSyncEventAndOneAuditRow(t *testing.T) {
	handler := liveHandler(t)

	before := countRows(t, "select count(*) from sync_event")
	beforeAudit := countRows(t, "select count(*) from audit_event where kind = 'sync'")

	body := `{"profile":"platform-baseline","revision":2,"host":"dev-laptop-01",` +
		`"targets":["claude-code","codex"],"skipped":["acme/legacy-helper"]}`
	rec := request(t, handler, http.MethodPost, "/v1/sync", kw.token, body)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())

	require.Equal(t, before+1, countRows(t, "select count(*) from sync_event"))
	require.Equal(t, beforeAudit+1, countRows(t, "select count(*) from audit_event where kind = 'sync'"))

	var text, source string
	require.NoError(t, pool.QueryRow(context.Background(),
		`select text, source from audit_event where kind = 'sync' order by occurred_at desc limit 1`).
		Scan(&text, &source))
	require.Contains(t, text, "platform-baseline r2")
	require.Contains(t, text, "claude-code")
	// FR-050: a client source identifies the host.
	require.Equal(t, "cli / dev-laptop-01", source)
}

func TestReportSyncRefusesAProfileTheIdentityCannotRead(t *testing.T) {
	handler := liveHandler(t)

	before := countRows(t, "select count(*) from sync_event")
	beforeAudit := countRows(t, "select count(*) from audit_event")

	body := `{"profile":"nobody-home","revision":1,"host":"dev-laptop-01","targets":["claude-code"]}`
	rec := request(t, handler, http.MethodPost, "/v1/sync", kw.token, body)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	require.Equal(t, before, countRows(t, "select count(*) from sync_event"))
	require.Equal(t, beforeAudit, countRows(t, "select count(*) from audit_event"),
		"a refused command writes nothing, audit row included")
}

// ---- reads through the wire --------------------------------------------------

func TestGetRevisionServesTheStoredLockfile(t *testing.T) {
	handler := liveHandler(t)

	for _, tc := range []struct {
		name, path, token string
		want              int
		wantRevision      int
	}{
		{"head is the newest revision", "/v1/profiles/platform-baseline/revisions/head", kw.token, http.StatusOK, 2},
		{"an exact revision is still readable", "/v1/profiles/platform-baseline/revisions/1", kw.token, http.StatusOK, 1},
		{"an unreadable profile is a 404, not a 403", "/v1/profiles/nobody-home/revisions/head", kw.token, http.StatusNotFound, 0},
		{"a profile that does not exist is the same 404", "/v1/profiles/no-such-thing/revisions/head", kw.token, http.StatusNotFound, 0},
		{"a revision that does not exist is a 404", "/v1/profiles/platform-baseline/revisions/99", kw.token, http.StatusNotFound, 0},
		{"no token is a 401", "/v1/profiles/platform-baseline/revisions/head", "", http.StatusUnauthorized, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, handler, http.MethodGet, tc.path, tc.token, "")
			require.Equal(t, tc.want, rec.Code, rec.Body.String())
			if tc.want != http.StatusOK {
				return
			}
			var lock contract.Lockfile
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &lock))
			require.Equal(t, tc.wantRevision, lock.Revision)
			require.Equal(t, "1.0.0", lock.SchemaVersion)
			// FR-036: the excluded package is reported with its reason.
			require.Len(t, lock.Skipped, 1)
			require.Equal(t, "flagged-awaiting-approval", lock.Skipped[0].Reason)
		})
	}
}

func TestGetBundleServesCleanBytesAndNeverARejectedVersion(t *testing.T) {
	handler := liveHandler(t)

	t.Run("a clean version is served with its digest", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/bundles/acme/code-review/2.4.1", kw.token, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, bundleBytes, rec.Body.Bytes())
		require.Equal(t, "application/zstd", rec.Header().Get("Content-Type"))
		require.Equal(t, "sha-256="+encodeBase64(bundleSHA), rec.Header().Get("Digest"))
		require.NotEmpty(t, rec.Header().Get("ETag"))
	})

	t.Run("a rejected version is refused whatever the gate says", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/bundles/acme/code-review/0.9.0", kw.token, "")
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	})

	t.Run("an unknown version is a 404", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/bundles/acme/code-review/9.9.9", kw.token, "")
		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	// The regression this guards: the query matched publisher.slug for a while, and
	// a slug is two segments, so every request 404'd. Matching one team's slug
	// would fix that test and still lose this one — `acme/security` publishes
	// threat-model, `acme/platform` publishes code-review, and both answer under
	// the same first segment because that segment is the namespace.
	t.Run("two teams in one namespace are both reachable through it", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/bundles/acme/threat-model/1.0.0", kw.token, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, siblingBytes, rec.Body.Bytes())
		require.Equal(t, "sha-256="+encodeBase64(siblingSHA), rec.Header().Get("Digest"))
	})

	t.Run("a package is not reachable through its publisher's team segment", func(t *testing.T) {
		rec := request(t, handler, http.MethodGet, "/v1/bundles/security/threat-model/1.0.0", kw.token, "")
		require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	})
}

func TestHealthIsGreenAgainstRealDependencies(t *testing.T) {
	rec := request(t, liveHandler(t), http.MethodGet, "/v1/health", "", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var body contract.Health
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "ok", body.Status)
	require.NotEmpty(t, body.Checks)
}

// ---- helpers -----------------------------------------------------------------

func countRows(t *testing.T, query string) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), query).Scan(&count)
	require.NoError(t, err)
	return count
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

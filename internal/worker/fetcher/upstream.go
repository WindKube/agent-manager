package fetcher

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/uptrace/bun"

	"agent-manager/internal/config"
	"agent-manager/internal/fetch"
	"agent-manager/internal/outbox"
	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
	"agent-manager/internal/worker"
)

// MaxNewVersionsPerCheck caps registrations per package per check, so a large
// backlog catches up gradually instead of flooding the fetch queue.
const MaxNewVersionsPerCheck = 5

// upstreamTimeout bounds one whole check of every tracked package.
const upstreamTimeout = 30 * time.Minute

const upstreamTrigger = "new upstream tag"

// UpstreamCheck is the periodic `upstream-check` job; every run checks every tracked package.
type UpstreamCheck struct{}

func (UpstreamCheck) Kind() string { return "upstream-check" }

// InsertOpts puts the check on the fetch queue, the only one this role works.
func (UpstreamCheck) InsertOpts() river.InsertOpts { return river.InsertOpts{Queue: outbox.QueueFetch} }

func periodic(cfg worker.Config) ([]worker.PeriodicJob, error) {
	if err := config.CheckUpstreamInterval(cfg.UpstreamInterval); err != nil {
		return nil, err
	}
	return []worker.PeriodicJob{{Interval: cfg.UpstreamInterval, Args: UpstreamCheck{}}}, nil
}

// Upstream works the `upstream-check` job.
type Upstream struct {
	river.WorkerDefaults[UpstreamCheck]

	deps worker.Deps
	git  fetch.GitSource
}

// NewUpstream assembles the check from what the bootstrap handed the role.
func NewUpstream(deps worker.Deps) (*Upstream, error) {
	switch {
	case deps.DB == nil:
		return nil, errors.New("upstream check: no database handle")
	case deps.Fetch == nil:
		return nil, errors.New("upstream check: no outbound client")
	}
	git, err := fetch.NewGitSource(deps.Fetch, deps.GitHubToken)
	if err != nil {
		return nil, fmt.Errorf("upstream check: %w", err)
	}
	return &Upstream{deps: deps, git: git}, nil
}

func (u *Upstream) Timeout(*river.Job[UpstreamCheck]) time.Duration { return upstreamTimeout }

func (u *Upstream) Work(ctx context.Context, _ *river.Job[UpstreamCheck]) error {
	return u.CheckAll(ctx)
}

// CheckAll checks every tracked package. A forge failure is recorded on that
// package; only a database failure fails the job.
func (u *Upstream) CheckAll(ctx context.Context) error {
	var ids []uuid.UUID
	if err := u.deps.DB.NewSelect().Model((*models.Package)(nil)).Column("id").
		Where("track_upstream").Order("namespace", "name").Scan(ctx, &ids); err != nil {
		return fmt.Errorf("list the tracked packages: %w", err)
	}
	var errs []error
	for _, id := range ids {
		if err := u.check(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// check lists tags outside any transaction, then registers new ones while
// holding the package row lock, so overlapping checks cannot both register a tag.
func (u *Upstream) check(ctx context.Context, packageID uuid.UUID) error {
	pkg := new(models.Package)
	if err := u.deps.DB.NewSelect().Model(pkg).Where("id = ?", packageID).Scan(ctx); err != nil {
		return fmt.Errorf("read tracked package %s: %w", packageID, err)
	}
	tags, listErr := u.git.Tags(ctx, fetch.SourceRef{Kind: fetch.SourceGit, URL: pkg.SourceURL})
	if listErr != nil && (errors.Is(listErr, context.Canceled) || errors.Is(listErr, context.DeadlineExceeded)) {
		return listErr
	}

	log := u.deps.Log.With().Str("job", "upstream-check").Str("package", pkg.Namespace+"/"+pkg.Name).Logger()
	registered := 0
	err := u.deps.DB.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		pkg = new(models.Package)
		if err := tx.NewSelect().Model(pkg).Where("id = ?", packageID).For("update").Scan(ctx); err != nil {
			return fmt.Errorf("lock tracked package %s: %w", packageID, err)
		}
		if !pkg.TrackUpstream {
			return nil
		}

		checkErr := ""
		if listErr != nil {
			checkErr = firstLine(listErr.Error())
		} else {
			candidates, selectErr := u.candidates(ctx, tx, pkg, tags)
			if selectErr != nil {
				return selectErr
			}
			for _, candidate := range candidates {
				if _, regErr := Register(ctx, tx, Registrar{
					Actor: auditActor, ActorKind: models.ActorKindSystem, Source: auditSource, Trigger: upstreamTrigger,
				}, pkg, NewVersion{
					Semver: candidate.Semver,
					Tags:   []string{},
					Source: JobSource{
						Kind: fetch.SourceGit, URL: pkg.SourceURL, Ref: candidate.Tag, Subdirectory: pkg.SourceSubdirectory,
					},
				}); regErr != nil {
					return regErr
				}
				registered++
			}
		}
		return recordCheck(ctx, tx, pkg, checkErr)
	})
	if err != nil {
		log.Error().Err(err).Msg("upstream check failed")
		return fmt.Errorf("upstream check of %s/%s: %w", pkg.Namespace, pkg.Name, err)
	}
	if listErr != nil {
		log.Warn().Err(listErr).Msg("listing the upstream tags failed")
	} else {
		log.Info().Int("registered", registered).Msg("upstream checked")
	}
	return nil
}

// candidates reads known versions under the row lock, so selection cannot race
// another registration.
func (u *Upstream) candidates(ctx context.Context, tx bun.IDB, pkg *models.Package, tags []fetch.Tag) ([]Candidate, error) {
	var known []string
	if err := tx.NewSelect().Model((*models.Version)(nil)).Column("semver").
		Where("package_id = ?", pkg.ID).Scan(ctx, &known); err != nil {
		return nil, fmt.Errorf("read the versions of %s/%s: %w", pkg.Namespace, pkg.Name, err)
	}
	names := make([]string, 0, len(tags))
	for _, tag := range tags {
		names = append(names, tag.Name)
	}
	return SelectTags(names, pkg.TagPattern, known, MaxNewVersionsPerCheck), nil
}

// recordCheck stamps the check. Only a change in the error column is audited.
func recordCheck(ctx context.Context, tx bun.IDB, pkg *models.Package, checkErr string) error {
	previous := pkg.LastCheckError
	if _, err := tx.NewUpdate().Model((*models.Package)(nil)).
		Set("last_checked_at = now()").
		Set("last_check_error = ?", nullIfEmpty(checkErr)).
		Where("id = ?", pkg.ID).Exec(ctx); err != nil {
		return fmt.Errorf("record the upstream check of %s/%s: %w", pkg.Namespace, pkg.Name, err)
	}
	if previous == checkErr {
		return nil
	}
	by := Registrar{Actor: auditActor, ActorKind: models.ActorKindSystem, Source: auditSource}
	subject := audit.Package(pkg.Namespace, pkg.Name)
	if checkErr == "" {
		return writeAudit(ctx, tx, by, "upstream-check-recovered",
			fmt.Sprintf("the upstream check of %s/%s succeeded again", pkg.Namespace, pkg.Name), subject, nil)
	}
	return writeAudit(ctx, tx, by, "upstream-check-failed",
		fmt.Sprintf("the upstream check of %s/%s failed: %s", pkg.Namespace, pkg.Name, checkErr), subject, nil)
}

// Candidate is an upstream tag to register, and the version it becomes.
type Candidate struct {
	Tag    string
	Semver string
}

// SelectTags picks tags matching pattern that parse as strict semver (one
// leading `v` allowed), have no build metadata and exceed every known version.
// Prereleases are kept only when pattern contains a `-`. The result is
// ascending and at most limit long, so a backlog registers oldest first.
func SelectTags(tags []string, pattern string, known []string, limit int) []Candidate {
	var newest *semver.Version
	for _, raw := range known {
		v, err := semver.NewVersion(raw)
		if err == nil && (newest == nil || v.GreaterThan(newest)) {
			newest = v
		}
	}
	wantPrerelease := strings.Contains(pattern, "-")

	type parsed struct {
		tag string
		v   *semver.Version
	}
	var picked []parsed
	seen := map[string]bool{}
	for _, tag := range tags {
		if ok, err := path.Match(pattern, tag); err != nil || !ok {
			continue
		}
		v, err := semver.StrictNewVersion(strings.TrimPrefix(tag, "v"))
		switch {
		case err != nil, v.Metadata() != "":
			continue
		case v.Prerelease() != "" && !wantPrerelease:
			continue
		case newest != nil && !v.GreaterThan(newest):
			continue
		case seen[v.String()]:
			continue
		}
		seen[v.String()] = true
		picked = append(picked, parsed{tag: tag, v: v})
	}
	slices.SortFunc(picked, func(a, b parsed) int { return a.v.Compare(b.v) })
	if len(picked) > limit {
		picked = picked[:limit]
	}
	out := make([]Candidate, 0, len(picked))
	for _, p := range picked {
		out = append(out, Candidate{Tag: p.tag, Semver: p.v.String()})
	}
	return out
}

// ValidTagPattern reports whether pattern is a glob path.Match can use.
func ValidTagPattern(pattern string) bool {
	if pattern == "" || len(pattern) > 100 {
		return false
	}
	_, err := path.Match(pattern, "")
	return err == nil
}

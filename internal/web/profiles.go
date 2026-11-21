package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// Profile writes use post-redirect-get, except a refusal the api understood, which
// renders inline so its text cannot be forged through a redirect link.

func (s *Server) profiles(c *gin.Context) {
	viewer := viewerFor(c)
	screen := view.Profiles{
		CanCreate: viewer != nil && viewer.HasRole,
		Notice:    profileNotice(c.Query("notice")),
	}

	rows, err := s.deps.Hub.Profiles(session(c))
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "profiles"); !ok {
		s.renderProfiles(c, status, screen)
		return
	}
	screen.Rows = rows
	s.renderProfiles(c, http.StatusOK, screen)
}

func (s *Server) renderProfiles(c *gin.Context, status int, screen view.Profiles) {
	s.render(c, status, "Profiles", "profiles", components.ProfilesScreen(screen))
}

func (s *Server) createProfile(c *gin.Context) {
	creation := hub.ProfileCreation{
		Slug:          strings.TrimSpace(c.PostForm("slug")),
		Name:          strings.TrimSpace(c.PostForm("name")),
		Description:   strings.TrimSpace(c.PostForm("description")),
		Visibility:    c.PostForm("visibility"),
		OwnerTeam:     strings.TrimSpace(c.PostForm("ownerTeam")),
		DefaultPolicy: c.PostForm("defaultPolicy"),
		ForkOf:        strings.TrimSpace(c.PostForm("forkOf")),
	}

	created, err := s.deps.Hub.CreateProfile(session(c), creation)
	switch {
	case err == nil:
		s.redirectProfiles(c, "/profiles/"+created.Slug, profileCreated)
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
	case errors.Is(err, hub.ErrForbidden):
		s.backToProfiles(c, profileRefusedRole)
	default:
		s.renderCreateProfileFailure(c, err)
	}
}

// renderCreateProfileFailure re-reads the list so the refusal sits above a real page.
func (s *Server) renderCreateProfileFailure(c *gin.Context, err error) {
	viewer := viewerFor(c)
	screen := view.Profiles{CanCreate: viewer != nil && viewer.HasRole}

	var refused *hub.ProfileRefusedError
	if errors.As(err, &refused) {
		screen.CreateRefused = refused.Detail
	} else {
		logFrom(c).Error().Err(err).Msg("create profile")
		screen.CreateRefused = "The hub could not create this profile. Its api may be unreachable."
	}

	if rows, readErr := s.deps.Hub.Profiles(session(c)); readErr == nil {
		screen.Rows = rows
	}
	s.renderProfiles(c, http.StatusUnprocessableEntity, screen)
}

func (s *Server) profileDetail(c *gin.Context) {
	slug := profileSlug(c)
	screen := view.Profile{Notice: profileNotice(c.Query("notice"))}

	detail, err := s.deps.Hub.Profile(session(c), slug)
	if errors.Is(err, view.ErrNotFound) {
		// Unreadable answers exactly as missing.
		screen.Missing = true
		s.renderProfile(c, http.StatusNotFound, screen)
		return
	}
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "profile detail"); !ok {
		s.renderProfile(c, status, screen)
		return
	}

	screen = detail
	screen.Notice = profileNotice(c.Query("notice"))
	if screen.Permissions.Curate {
		screen.AddOptions = s.availablePackages(session(c), detail.Entries)
	}
	if raw := c.Query("revision"); raw != "" {
		screen.Diff = s.revisionDiff(session(c), slug, raw)
	}
	s.renderProfile(c, http.StatusOK, screen)
}

// revisionDiff fetches revision N and its predecessor for view.DiffRevisions.
func (s *Server) revisionDiff(ctx context.Context, slug, raw string) *view.RevisionDiffPanel {
	revision, err := strconv.Atoi(raw)
	if err != nil || revision < 1 {
		return &view.RevisionDiffPanel{Missing: true}
	}

	newer, err := s.deps.Hub.Revision(ctx, slug, revision)
	if err != nil {
		return &view.RevisionDiffPanel{Revision: revision, Missing: true}
	}

	if revision == 1 {
		return &view.RevisionDiffPanel{Revision: revision, Diff: view.DiffRevisions(newer, nil)}
	}

	older, err := s.deps.Hub.Revision(ctx, slug, revision-1)
	if err != nil {
		// Never render a missing predecessor as an empty diff.
		return &view.RevisionDiffPanel{Revision: revision, PredecessorUnavailable: true}
	}
	return &view.RevisionDiffPanel{Revision: revision, Diff: view.DiffRevisions(newer, &older)}
}

// maxAddOptionPages is generous because the catalog is a short admin-reviewed list, not an open registry.
const maxAddOptionPages = 50

// availablePackages lists catalog packages the profile lacks. A catalog failure
// yields no options so the Add control degrades instead of failing the page.
func (s *Server) availablePackages(ctx context.Context, held []view.ProfileEntryRow) []view.ProfileAddOption {
	holding := make(map[string]struct{}, len(held))
	for i := range held {
		holding[held[i].ID] = struct{}{}
	}

	var options []view.ProfileAddOption
	q := view.CatalogQuery{Sort: view.SortName, Dir: view.DirAsc}
	for page := 1; page <= maxAddOptionPages; page++ {
		q.Page = page
		result, err := s.deps.Hub.Catalog(ctx, q)
		if err != nil {
			return nil
		}
		for i := range result.Rows {
			row := &result.Rows[i]
			if _, ok := holding[row.ID]; !ok {
				options = append(options, view.ProfileAddOption{ID: row.ID, Name: row.Name, Kind: row.Kind})
			}
		}
		if page >= result.Pages() {
			break
		}
	}
	return options
}

func (s *Server) renderProfile(c *gin.Context, status int, screen view.Profile) {
	s.render(c, status, "Profile", "profiles", components.ProfileScreen(screen))
}

func profileSlug(c *gin.Context) string {
	return strings.TrimPrefix(c.Param("slug"), "/")
}

func profileSlugForm(c *gin.Context) string {
	return strings.TrimSpace(c.PostForm("slug"))
}

// addEntry defaults to latest because the package screen's plain Add form sends
// no mode. An id already held is a race, treated as a mode change.
func (s *Server) addEntry(c *gin.Context) {
	slug := profileSlugForm(c)
	id := strings.TrimSpace(c.PostForm("id"))
	mode := c.DefaultPostForm("mode", "latest")
	version := c.PostForm("version")

	if id == "" {
		s.backToProfile(c, slug, profileEntryMissing)
		return
	}

	ctx := session(c)
	detail, err := s.deps.Hub.Profile(ctx, slug)
	if err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}

	settings := make([]hub.EntrySetting, 0, len(detail.Entries)+1)
	found := false
	for i := range detail.Entries {
		entry := &detail.Entries[i]
		setting := entrySettingFor(entry)
		if entry.ID == id {
			setting.Mode = mode
			setting.Version = version
			found = true
		}
		settings = append(settings, setting)
	}
	outcome := profileEntryAdded
	if !found {
		settings = append(settings, hub.EntrySetting{ID: id, Mode: mode, Version: version})
	} else {
		outcome = profileEntryUpdated
	}

	if _, err := s.deps.Hub.SetProfileEntries(ctx, slug, settings); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.backToProfile(c, slug, outcome)
}

// removeEntry uses the dedicated command: SetProfileEntries refuses a set that omits a held entry.
func (s *Server) removeEntry(c *gin.Context) {
	slug := profileSlugForm(c)
	id := strings.TrimSpace(c.PostForm("id"))

	if id == "" {
		s.backToProfile(c, slug, profileEntryMissing)
		return
	}

	if _, err := s.deps.Hub.RemoveProfileEntry(session(c), slug, id); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.backToProfile(c, slug, profileEntryRemoved)
}

func (s *Server) pinEntry(c *gin.Context) { s.setEntryMode(c, "pinned") }

func (s *Server) floatEntry(c *gin.Context) { s.setEntryMode(c, "latest") }

// setEntryMode resends every other entry unchanged, since SetProfileEntries takes the whole set.
func (s *Server) setEntryMode(c *gin.Context, mode string) {
	slug := profileSlugForm(c)
	id := c.PostForm("id")

	ctx := session(c)
	detail, err := s.deps.Hub.Profile(ctx, slug)
	if err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}

	settings := make([]hub.EntrySetting, 0, len(detail.Entries))
	found := false
	for i := range detail.Entries {
		entry := &detail.Entries[i]
		setting := entrySettingFor(entry)
		if entry.ID == id {
			setting.Mode = mode
			if mode == "pinned" {
				setting.Version = c.PostForm("version")
			} else {
				setting.Version = ""
			}
			found = true
		}
		settings = append(settings, setting)
	}
	if !found {
		s.backToProfile(c, slug, profileEntryMissing)
		return
	}

	if _, err := s.deps.Hub.SetProfileEntries(ctx, slug, settings); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.backToProfile(c, slug, profileEntryUpdated)
}

func entrySettingFor(entry *view.ProfileEntryRow) hub.EntrySetting {
	setting := hub.EntrySetting{ID: entry.ID, Mode: entry.Mode}
	switch entry.Mode {
	case "pinned":
		setting.Version = entry.PinnedVersion
	case "range":
		setting.Version = entry.Range
	}
	return setting
}

func (s *Server) shareProfile(c *gin.Context) {
	slug := profileSlugForm(c)
	share := hub.Share{
		Kind: c.PostForm("kind"),
		Ref:  strings.TrimSpace(c.PostForm("ref")),
		Role: c.PostForm("role"),
	}

	if _, err := s.deps.Hub.SetProfileSharing(session(c), slug, []hub.Share{share}); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.backToProfile(c, slug, profileShared)
}

func (s *Server) setTargets(c *gin.Context) {
	slug := profileSlugForm(c)
	targets := c.PostFormArray("targets")
	if _, err := s.deps.Hub.SetProfileTargets(session(c), slug, targets); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.backToProfile(c, slug, profileTargetsSaved)
}

func (s *Server) publishRevision(c *gin.Context) {
	slug := profileSlugForm(c)
	note := strings.TrimSpace(c.PostForm("note"))
	if err := s.deps.Hub.PublishRevision(session(c), slug, note); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.backToProfile(c, slug, profilePublished)
}

func (s *Server) deleteProfile(c *gin.Context) {
	slug := profileSlugForm(c)
	if err := s.deps.Hub.DeleteProfile(session(c), slug); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.redirectProfiles(c, "/profiles", profileDeleted)
}

// profileWriteFailed maps a curation write's error onto a redirect, except a
// refusal the api understood (hub.ProfileRefusedError), which renders inline
// against a fresh read so a redirect can't turn it into forgeable link text.
func (s *Server) profileWriteFailed(c *gin.Context, slug string, err error) {
	switch {
	case errors.Is(err, view.ErrSignedOut):
		s.toSignIn(c)
	case errors.Is(err, hub.ErrForbidden):
		s.backToProfile(c, slug, profileRefusedRole)
	case errors.Is(err, view.ErrNotFound):
		s.backToProfile(c, slug, profileMissing)
	default:
		var refused *hub.ProfileRefusedError
		if errors.As(err, &refused) {
			s.renderProfileRefusal(c, slug, refused.Detail)
			return
		}
		logFrom(c).Error().Err(err).Msg("profile write failed")
		s.backToProfile(c, slug, profileFailed)
	}
}

func (s *Server) renderProfileRefusal(c *gin.Context, slug, detail string) {
	screen := view.Profile{GovernanceState: view.GovernanceState{Unavailable: true}, Refusal: detail}
	if fresh, err := s.deps.Hub.Profile(session(c), slug); err == nil {
		screen = fresh
		screen.Refusal = detail
	}
	s.renderProfile(c, http.StatusUnprocessableEntity, screen)
}

type profileOutcome string

const (
	profileCreated      profileOutcome = "created"
	profileEntryAdded   profileOutcome = "entry-added"
	profileEntryUpdated profileOutcome = "entry-updated"
	profileEntryRemoved profileOutcome = "entry-removed"
	profileEntryMissing profileOutcome = "entry-missing"
	profileShared       profileOutcome = "shared"
	profileTargetsSaved profileOutcome = "targets-saved"
	profilePublished    profileOutcome = "published"
	profileDeleted      profileOutcome = "deleted"
	profileRefusedRole  profileOutcome = "refused-role"
	profileMissing      profileOutcome = "missing"
	profileFailed       profileOutcome = "failed"
)

func profileNotice(raw string) *view.Notice {
	switch profileOutcome(raw) {
	case profileCreated:
		return &view.Notice{Tone: "ok", Text: "Profile created. It holds no packages yet."}
	case profileEntryAdded:
		return &view.Notice{Tone: "ok", Text: "Package added, floating to latest. Not durable " +
			"until a revision is published."}
	case profileEntryUpdated:
		return &view.Notice{Tone: "ok", Text: "Saved. This is not durable until a revision is " +
			"published — no machine has seen it yet."}
	case profileEntryRemoved:
		return &view.Notice{Tone: "ok", Text: "Removed. This is not durable until a revision is " +
			"published — the package still reaches any machine on the head revision until then."}
	case profileShared:
		return &view.Notice{Tone: "ok", Text: "Sharing updated."}
	case profileTargetsSaved:
		return &view.Notice{Tone: "ok", Text: "Sync targets saved. This changes only what a " +
			"client writes locally; nothing server-side changed."}
	case profilePublished:
		return &view.Notice{Tone: "ok", Text: "Revision published. The previous revision stays " +
			"readable, and a synced machine picks this one up on its next sync."}
	case profileDeleted:
		return &view.Notice{Tone: "ok", Text: "Profile deleted."}
	case profileRefusedRole:
		return &view.Notice{Tone: "dan", Text: "Your role on this profile may not take that " +
			"action, so nothing was recorded."}
	case profileEntryMissing:
		return &view.Notice{Tone: "warn", Text: "That package is no longer in this profile, so " +
			"there was nothing to change. Reload — this screen may be stale."}
	case profileMissing:
		return &view.Notice{Tone: "dan", Text: "No such profile, or it is not readable by your " +
			"identity."}
	case profileFailed:
		return &view.Notice{Tone: "dan", Text: "The hub refused that change and recorded " +
			"nothing. Reload — this screen may be stale."}
	default:
		return nil
	}
}

func (s *Server) backToProfiles(c *gin.Context, outcome profileOutcome) {
	s.redirectProfiles(c, "/profiles", outcome)
}

func (s *Server) backToProfile(c *gin.Context, slug string, outcome profileOutcome) {
	s.redirectProfiles(c, "/profiles/"+slug, outcome)
}

func (s *Server) redirectProfiles(c *gin.Context, target string, outcome profileOutcome) {
	parsed, err := url.Parse(target)
	if err != nil {
		parsed = &url.URL{Path: "/profiles"}
	}
	values := parsed.Query()
	values.Set("notice", string(outcome))
	parsed.RawQuery = values.Encode()

	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusSeeOther, parsed.String())
}

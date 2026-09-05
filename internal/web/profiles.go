package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"agent-manager/internal/web/components"
	"agent-manager/internal/web/hub"
	"agent-manager/internal/web/view"
)

// The two profile screens.
//
// Plain server renders and plain form posts, like the scanner screen: curating
// a profile changes stored state, so post-redirect-get is what makes a reload
// safe. The one exception is a refusal the api understood — the slug is taken,
// the visibility is not a value it knows — which is rendered inline on the
// same request rather than carried through a redirect, so the sentence a
// person reads is one this exact request received rather than one a forwarded
// link could have put in the hub's mouth.

func (s *Server) profiles(c *gin.Context) {
	viewer := viewerFor(c)
	screen := view.Profiles{
		CanCreate: viewer != nil && viewer.HasRole,
		Notice:    profileNotice(c.Query("notice")),
	}

	if s.deps.Profiles == nil {
		screen.Unavailable = true
		s.renderProfiles(c, http.StatusBadGateway, screen)
		return
	}

	rows, err := s.deps.Profiles.Profiles(session(c))
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "profiles"); !ok {
		s.renderProfiles(c, status, screen)
		return
	}
	for _, row := range rows {
		screen.Rows = append(screen.Rows, profileRow(row))
	}
	s.renderProfiles(c, http.StatusOK, screen)
}

func (s *Server) renderProfiles(c *gin.Context, status int, screen view.Profiles) {
	s.render(c, status, "Profiles", "profiles", components.ProfilesScreen(screen))
}

func (s *Server) createProfile(c *gin.Context) {
	if s.deps.Profiles == nil || s.deps.Curator == nil {
		s.backToProfiles(c, profileUnavailable)
		return
	}

	creation := hub.ProfileCreation{
		Slug:          strings.TrimSpace(c.PostForm("slug")),
		Name:          strings.TrimSpace(c.PostForm("name")),
		Description:   strings.TrimSpace(c.PostForm("description")),
		Visibility:    c.PostForm("visibility"),
		OwnerTeam:     strings.TrimSpace(c.PostForm("ownerTeam")),
		DefaultPolicy: c.PostForm("defaultPolicy"),
		ForkOf:        strings.TrimSpace(c.PostForm("forkOf")),
	}

	created, err := s.deps.Curator.CreateProfile(session(c), creation)
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

// renderCreateProfileFailure re-reads the list so the refusal appears above a
// real page rather than a blank one, and renders the api's own sentence
// (hub.ProfileRefusedError) or a generic one for anything else.
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

	if s.deps.Profiles != nil {
		if rows, readErr := s.deps.Profiles.Profiles(session(c)); readErr == nil {
			for _, row := range rows {
				screen.Rows = append(screen.Rows, profileRow(row))
			}
		}
	}
	s.renderProfiles(c, http.StatusUnprocessableEntity, screen)
}

func (s *Server) profileDetail(c *gin.Context) {
	slug := profileSlug(c)
	screen := view.Profile{Notice: profileNotice(c.Query("notice"))}

	if s.deps.Profiles == nil {
		screen.Unavailable = true
		s.renderProfile(c, http.StatusBadGateway, screen)
		return
	}

	detail, err := s.deps.Profiles.Profile(session(c), slug)
	if errors.Is(err, view.ErrNotFound) {
		// An unreadable profile answers exactly as a missing one, so this is the
		// screen and not one of the three GovernanceState reasons.
		screen.Missing = true
		s.renderProfile(c, http.StatusNotFound, screen)
		return
	}
	if status, ok := s.governanceFailure(c, err, &screen.GovernanceState, "profile detail"); !ok {
		s.renderProfile(c, status, screen)
		return
	}

	screen = profileScreen(detail)
	screen.Notice = profileNotice(c.Query("notice"))
	if screen.Permissions.Curate && s.deps.Catalog != nil {
		screen.AddOptions = s.availablePackages(session(c), detail.Entries)
	}
	s.renderProfile(c, http.StatusOK, screen)
}

// maxAddOptionPages bounds how much of the catalog is walked to build the "Add
// package" list. The catalog this hub curates is a short, admin-reviewed
// vocabulary (FR-049), not an open registry, so this is generous rather than
// tight.
const maxAddOptionPages = 50

// availablePackages lists every catalog package this profile does not already
// hold. A catalog read failure yields no options rather than an error: the
// screen has already rendered on the profile read succeeding, and the Add
// control degrading to absent is better than the whole page failing on it.
func (s *Server) availablePackages(ctx context.Context, held []hub.ProfileEntry) []view.ProfileAddOption {
	holding := make(map[string]struct{}, len(held))
	for i := range held {
		holding[held[i].ID] = struct{}{}
	}

	var options []view.ProfileAddOption
	q := view.CatalogQuery{Sort: view.SortName, Dir: view.DirAsc}
	for page := 1; page <= maxAddOptionPages; page++ {
		q.Page = page
		result, err := s.deps.Catalog.Catalog(ctx, q)
		if err != nil {
			return nil
		}
		for i := range result.Rows {
			row := &result.Rows[i]
			if _, ok := holding[row.ID]; !ok {
				options = append(options, view.ProfileAddOption{ID: row.ID, Name: row.Name})
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

// profileSlug reads the catch-all param the detail route captures, which gin
// includes with its leading "/".
func profileSlug(c *gin.Context) string {
	return strings.TrimPrefix(c.Param("slug"), "/")
}

// profileSlugForm is the slug a write route reads from its form body, because
// none of those routes carries one as a path segment (see web.go's routing
// comment).
func profileSlugForm(c *gin.Context) string {
	return strings.TrimSpace(c.PostForm("slug"))
}

// ---- the writes -----------------------------------------------------------

// addEntry adds a package the profile does not yet hold, floating latest. An
// id already held is not an error — the select only ever offers ids the
// profile lacks, so this is a race rather than a mistake — and it takes the
// same path as floating an existing entry to latest.
func (s *Server) addEntry(c *gin.Context) {
	slug := profileSlugForm(c)
	id := strings.TrimSpace(c.PostForm("id"))

	if s.deps.Profiles == nil || s.deps.Curator == nil {
		s.backToProfile(c, slug, profileUnavailable)
		return
	}
	if id == "" {
		s.backToProfile(c, slug, profileEntryMissing)
		return
	}

	ctx := session(c)
	detail, err := s.deps.Profiles.Profile(ctx, slug)
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
			setting.Mode = "latest"
			setting.Version = ""
			found = true
		}
		settings = append(settings, setting)
	}
	outcome := profileEntryAdded
	if !found {
		settings = append(settings, hub.EntrySetting{ID: id, Mode: "latest"})
	} else {
		// Already held: nothing new to add, so this is the same outcome floating
		// an existing entry to latest already reports.
		outcome = profileEntryUpdated
	}

	if _, err := s.deps.Curator.SetProfileEntries(ctx, slug, settings); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.backToProfile(c, slug, outcome)
}

func (s *Server) pinEntry(c *gin.Context) { s.setEntryMode(c, "pinned") }

func (s *Server) floatEntry(c *gin.Context) { s.setEntryMode(c, "latest") }

// setEntryMode floats or pins one package, leaving every other entry's setting
// exactly as it stood (SetProfileEntries takes the whole ordered set, so the
// other rows are read back before being resent).
func (s *Server) setEntryMode(c *gin.Context, mode string) {
	slug := profileSlugForm(c)
	id := c.PostForm("id")

	if s.deps.Profiles == nil || s.deps.Curator == nil {
		s.backToProfile(c, slug, profileUnavailable)
		return
	}

	ctx := session(c)
	detail, err := s.deps.Profiles.Profile(ctx, slug)
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

	if _, err := s.deps.Curator.SetProfileEntries(ctx, slug, settings); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.backToProfile(c, slug, profileEntryUpdated)
}

func entrySettingFor(entry *hub.ProfileEntry) hub.EntrySetting {
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
	if s.deps.Curator == nil {
		s.backToProfile(c, slug, profileUnavailable)
		return
	}

	share := hub.Share{
		Kind: c.PostForm("kind"),
		Ref:  strings.TrimSpace(c.PostForm("ref")),
		Role: c.PostForm("role"),
	}

	if _, err := s.deps.Curator.SetProfileSharing(session(c), slug, []hub.Share{share}); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.backToProfile(c, slug, profileShared)
}

func (s *Server) setTargets(c *gin.Context) {
	slug := profileSlugForm(c)
	if s.deps.Curator == nil {
		s.backToProfile(c, slug, profileUnavailable)
		return
	}

	targets := c.PostFormArray("targets")
	if _, err := s.deps.Curator.SetProfileTargets(session(c), slug, targets); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.backToProfile(c, slug, profileTargetsSaved)
}

func (s *Server) publishRevision(c *gin.Context) {
	slug := profileSlugForm(c)
	if s.deps.Curator == nil {
		s.backToProfile(c, slug, profileUnavailable)
		return
	}

	note := strings.TrimSpace(c.PostForm("note"))
	if _, err := s.deps.Curator.PublishRevision(session(c), slug, note); err != nil {
		s.profileWriteFailed(c, slug, err)
		return
	}
	s.backToProfile(c, slug, profilePublished)
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
	if s.deps.Profiles != nil {
		if fresh, err := s.deps.Profiles.Profile(session(c), slug); err == nil {
			screen = profileScreen(fresh)
			screen.Refusal = detail
		}
	}
	s.renderProfile(c, http.StatusUnprocessableEntity, screen)
}

// ---- redirects and notices -------------------------------------------------

type profileOutcome string

const (
	profileCreated      profileOutcome = "created"
	profileEntryAdded   profileOutcome = "entry-added"
	profileEntryUpdated profileOutcome = "entry-updated"
	profileEntryMissing profileOutcome = "entry-missing"
	profileShared       profileOutcome = "shared"
	profileTargetsSaved profileOutcome = "targets-saved"
	profilePublished    profileOutcome = "published"
	profileRefusedRole  profileOutcome = "refused-role"
	profileMissing      profileOutcome = "missing"
	profileUnavailable  profileOutcome = "unavailable"
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
	case profileShared:
		return &view.Notice{Tone: "ok", Text: "Sharing updated."}
	case profileTargetsSaved:
		return &view.Notice{Tone: "ok", Text: "Sync targets saved. This changes only what a " +
			"client writes locally; nothing server-side changed."}
	case profilePublished:
		return &view.Notice{Tone: "ok", Text: "Revision published. The previous revision stays " +
			"readable, and a synced machine picks this one up on its next sync."}
	case profileRefusedRole:
		return &view.Notice{Tone: "dan", Text: "Your role on this profile may not take that " +
			"action, so nothing was recorded."}
	case profileEntryMissing:
		return &view.Notice{Tone: "warn", Text: "That package is no longer in this profile, so " +
			"there was nothing to change. Reload — this screen may be stale."}
	case profileMissing:
		return &view.Notice{Tone: "dan", Text: "No such profile, or it is not readable by your " +
			"identity."}
	case profileUnavailable:
		return &view.Notice{Tone: "dan", Text: "The hub's api could not be reached, so nothing " +
			"was recorded."}
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

// redirectProfiles is the profile screens' half of post-redirect-get.
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

// ---- mapping the hub's answers onto the screen's models -------------------

func profileRow(from hub.ProfileSummary) view.ProfileRow {
	return view.ProfileRow{
		Slug: from.Slug, Name: from.Name, Visibility: from.Visibility,
		PackageCount: from.PackageCount, HeadRevision: from.HeadRevision,
	}
}

func profileScreen(from hub.ProfileDetail) view.Profile {
	out := view.Profile{
		Slug: from.Slug, Name: from.Name, Description: from.Description,
		Visibility: from.Visibility, OwnerTeam: from.OwnerTeam,
		DefaultPolicy: from.DefaultPolicy, Gate: from.Gate,
		HeadRevision: from.HeadRevision, ForkedFrom: from.ForkedFrom,
		Role: from.Role,
		Permissions: view.ProfilePermissions{
			Curate: from.Permissions.Curate, Share: from.Permissions.Share,
			Publish: from.Permissions.Publish,
		},
		UnpublishedChanges: from.UnpublishedChanges,
	}
	for i := range from.Entries {
		out.Entries = append(out.Entries, profileEntryRow(&from.Entries[i]))
	}
	for _, member := range from.Members {
		out.Members = append(out.Members, view.ProfileMemberRow{
			Kind: member.Kind, Ref: member.Ref, Role: member.Role,
			DisplayName: member.DisplayName,
		})
	}
	for _, target := range from.Targets {
		out.Targets = append(out.Targets, view.ProfileTargetRow{Target: target.Target, Enabled: target.Enabled})
	}
	for _, revision := range from.Revisions {
		out.Revisions = append(out.Revisions, view.ProfileRevisionRow{
			Revision: revision.Revision, Note: revision.Note,
			PublishedAt: view.Timestamp(revision.PublishedAt), PublishedBy: revision.PublishedBy,
		})
	}
	return out
}

func profileEntryRow(from *hub.ProfileEntry) view.ProfileEntryRow {
	entry := view.ProfileEntryRow{
		ID: from.ID, Name: from.Name, Kind: view.Kind(from.Kind),
		Mode: from.Mode, Range: from.Range, PinnedVersion: from.PinnedVersion,
		LatestVersion: from.LatestVersion, LatestVerdict: view.Verdict(from.LatestVerdict),
		Version: from.Version, Verdict: view.Verdict(from.Verdict), Digest: from.Digest,
		Outcome: view.ProfileOutcome(from.Outcome), Note: from.Note,
		Unpublished: from.Unpublished,
	}
	if from.Skip != nil {
		entry.Skip = &view.ProfileSkip{
			Reason: from.Skip.Reason, Detail: from.Skip.Detail,
			WouldHaveResolvedTo: from.Skip.WouldHaveResolvedTo,
		}
	}
	if from.Override != nil {
		override := view.ProfileOverride{Reviewer: from.Override.Reviewer, Note: from.Override.Note}
		if from.Override.ExpiresAt != nil {
			override.Expires = view.Timestamp(*from.Override.ExpiresAt)
		}
		entry.Override = &override
	}
	return entry
}

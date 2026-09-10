package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// The profile screen's door to the api, through the generated client and
// nothing else. Nothing here renders — no relative dates, no collapsed pills
// — because deciding what a gate outcome MEANS is the resolver's job and
// deciding how it READS is the screen's.
//
// Three refusals, three screens: 401 is signed out, 403 is a role that may
// not do this, 404 is a profile that does not exist or is not readable
// (answered identically on purpose, and never told apart here). A 409 or 422
// means the caller is permitted and the api understood but refuses, so it
// arrives as ProfileRefusedError carrying that sentence. Everything else is
// the api unreachable or broken, rendered as a bad gateway.
//
// Note, Skip.Detail and a member's DisplayName quote content this hub did
// not write. Render them escaped, always.

// ProfileRefusedError is the api refusing a curation request it understood
// from a caller it permitted: the slug is taken, the body leaves out a
// package the profile holds, the change would leave the profile with no
// owner. It carries the api's own sentence because the sentence IS the answer.
type ProfileRefusedError struct {
	// Detail is the api's RFC 9457 problem detail, quoting what the caller
	// sent: render it escaped.
	Detail string
}

func (e *ProfileRefusedError) Error() string { return e.Detail }

// ProfileDetail is one profile as the detail screen draws it.
type ProfileDetail struct {
	Slug        string
	Name        string
	Description string
	Visibility  string
	OwnerTeam   string

	DefaultPolicy string
	// Gate is the org gate in force NOW, which Entries were resolved under —
	// not the gate the head revision froze; the two disagreeing is part of
	// what UnpublishedChanges reports.
	Gate         string
	HeadRevision int
	// ForkedFrom is lineage and nothing else: a fork never inherits the
	// upstream's later revisions.
	ForkedFrom string

	// Role is legitimately empty: most readers of an org-visibility profile
	// hold no membership, so "no role" is a state, not a missing value.
	Role        string
	Permissions ProfilePermissions

	UnpublishedChanges bool

	Entries   []ProfileEntry
	Members   []ProfileMember
	Targets   []ProfileTarget
	Revisions []ProfileRevision
}

// ProfilePermissions is the api's answer to what this identity may do here,
// so a screen can disable a control rather than offer one that will be
// refused. It is the screen's copy of the answer, never the mechanism: the
// operations enforce this themselves regardless of what a browser was shown.
type ProfilePermissions struct {
	Curate  bool
	Share   bool
	Publish bool
}

// ProfileEntry is one package in a profile, with two version pairs. Latest*
// are the CATALOG's newest offering and its scan state, unaffected by what
// the gate does. Version/Verdict are what the entry actually resolves to,
// empty exactly when excluded.
type ProfileEntry struct {
	ID   string
	Name string
	Kind string

	// Mode is the profile's setting, not a label for what happened: a pin
	// the gate refused is still a pin.
	Mode          string
	Range         string
	PinnedVersion string

	LatestVersion string
	LatestVerdict string

	Version string
	Verdict string
	Digest  string

	Outcome string
	Note    string
	// Skip is present exactly when Outcome is skipped: an excluded package is
	// reported with its reason, never silently dropped.
	Skip *Skip
	// Override is the ACTIVE acceptance that let a flagged version through.
	Override *EntryOverride

	// Unpublished says this row would resolve differently from the head
	// revision's lockfile; either way no machine has seen it.
	Unpublished bool
}

// Skip is one excluded package and why. Reason is the canonical code and
// Detail is the resolver's prose about the finding that caused it.
type Skip struct {
	ID                  string
	Reason              string
	Detail              string
	WouldHaveResolvedTo string
}

// EntryOverride is the acceptance a flagged version resolved under — a type
// of its own rather than governance.go's Override, since that one is the
// decision as the scanner screen records it and this is what the resolver applied.
type EntryOverride struct {
	Reviewer string
	Note     string
	// ExpiresAt is nil when the acceptance does not lapse. The api's wire
	// shape models "no expiry" as the ZERO instant (the schema requires the
	// field), so it is turned back into absence here, at the door, rather
	// than in every screen that formats a date.
	ExpiresAt *time.Time
}

// ProfileMember is one subject the profile is shared with. A group is
// matched against the identity provider's claim on every request rather
// than expanded into people, which is why Kind travels.
type ProfileMember struct {
	Kind string
	Ref  string
	Role string
	// DisplayName is empty for a membership naming somebody this hub has
	// never seen sign in.
	DisplayName string
}

// ProfileTarget is one agent directory convention and whether this profile
// enables it. The api answers with the WHOLE vocabulary so a screen draws
// the same checkboxes without holding a copy of the enum.
type ProfileTarget struct {
	Target  string
	Enabled bool
}

// ProfileRevision is one published revision, as the history panel lists it.
type ProfileRevision struct {
	Revision    int
	Note        string
	PublishedAt time.Time
	PublishedBy string
}

// ProfileSummary is a profile as the list names it — and what creating one
// answers with.
type ProfileSummary struct {
	Slug         string
	Name         string
	Visibility   string
	PackageCount int
	HeadRevision int
}

// ProfileCreation is the create form. Every optional field is omitted from
// the request when empty, which is what makes the api's defaults apply — an
// empty string would sit outside every enum and be refused.
type ProfileCreation struct {
	Slug string
	Name string

	Description   string
	Visibility    string
	OwnerTeam     string
	DefaultPolicy string
	// ForkOf copies the named profile's entries as they stand now, and
	// records lineage only.
	ForkOf string
}

// EntrySetting is one package's version policy. Version carries the pin or
// range depending on Mode and is unused for latest.
type EntrySetting struct {
	ID      string
	Mode    string
	Version string
}

// Share is one subject and the role they are to hold.
type Share struct {
	Kind string
	Ref  string
	Role string
}

// PublishedRevision is what a publish froze. Deliberately not the whole
// lockfile — the bundle object keys and signature refs are in it and no
// screen may show either. What is here is what the confirmation states.
type PublishedRevision struct {
	// Revision is the number the SERVER allocated: a concurrent publish may
	// hold the one the caller expected, so this is the only place to learn it.
	Revision   int
	Note       string
	ResolvedAt time.Time
	Gate       string
	Entries    []LockedEntry
	// Skipped: a revision that excluded a package says so, rather than
	// announcing a clean publish.
	Skipped []Skip
}

// LockedEntry is one package frozen at an exact version.
type LockedEntry struct {
	ID         string
	Kind       string
	Version    string
	Digest     string
	Resolution string
	Verdict    string
	Override   *EntryOverride
}

// Profiles reads GET /v1/profiles: exactly the profiles this identity may read.
func (c *Client) Profiles(ctx context.Context) ([]ProfileSummary, error) {
	resp, err := c.api.ListProfilesWithResponse(ctx)
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	if resp.JSON200 == nil {
		return nil, fmt.Errorf("list profiles: %w", governanceError(resp.HTTPResponse, resp.Body))
	}

	out := make([]ProfileSummary, 0, len(resp.JSON200.Profiles))
	for i := range resp.JSON200.Profiles {
		out = append(out, profileSummary(&resp.JSON200.Profiles[i]))
	}
	return out, nil
}

// Profile reads GET /v1/profiles/{slug}.
func (c *Client) Profile(ctx context.Context, slug string) (ProfileDetail, error) {
	if err := checkSlug(slug); err != nil {
		return ProfileDetail{}, err
	}

	resp, err := c.api.GetProfileWithResponse(ctx, slug)
	if err != nil {
		return ProfileDetail{}, fmt.Errorf("get profile %s: %w", slug, err)
	}
	if resp.JSON200 == nil {
		return ProfileDetail{}, profileFailure("get profile "+slug, resp.HTTPResponse, resp.Body)
	}
	return profileDetail(resp.JSON200), nil
}

// CreateProfile posts POST /v1/profiles.
func (c *Client) CreateProfile(ctx context.Context, creation ProfileCreation) (ProfileSummary, error) {
	body := apiclient.CreateProfileJSONRequestBody{Slug: creation.Slug, Name: creation.Name}
	if creation.Description != "" {
		body.Description = &creation.Description
	}
	if creation.Visibility != "" {
		body.Visibility = ptr(apiclient.ProfileCreateVisibility(creation.Visibility))
	}
	if creation.OwnerTeam != "" {
		body.OwnerTeam = &creation.OwnerTeam
	}
	if creation.DefaultPolicy != "" {
		body.DefaultPolicy = ptr(apiclient.ProfileCreateDefaultPolicy(creation.DefaultPolicy))
	}
	if creation.ForkOf != "" {
		body.ForkOf = &creation.ForkOf
	}

	resp, err := c.api.CreateProfileWithResponse(ctx, body)
	if err != nil {
		return ProfileSummary{}, fmt.Errorf("create profile %s: %w", creation.Slug, err)
	}
	if resp.JSON201 == nil {
		return ProfileSummary{}, profileFailure("create profile "+creation.Slug,
			resp.HTTPResponse, resp.Body)
	}

	return profileSummary(resp.JSON201), nil
}

func profileSummary(from *apiclient.Profile) ProfileSummary {
	summary := ProfileSummary{
		Slug:         from.Slug,
		Name:         from.Name,
		PackageCount: int(from.PackageCount),
		HeadRevision: int(from.HeadRevision),
	}
	if from.Visibility != nil {
		summary.Visibility = string(*from.Visibility)
	}
	return summary
}

// SetProfileEntries puts PUT /v1/profiles/{slug}/entries — the WHOLE ordered
// set, since position is what an ordered set means and a patch cannot
// express a reorder. An empty slice is refused by the api naming every
// package left out: there is no removal, on this path or any other.
func (c *Client) SetProfileEntries(ctx context.Context, slug string, entries []EntrySetting) (ProfileDetail, error) {
	if err := checkSlug(slug); err != nil {
		return ProfileDetail{}, err
	}

	// Built with a length rather than left nil so an empty set is sent as
	// `[]`, not the `null` a nil slice marshals to.
	body := apiclient.SetProfileEntriesJSONRequestBody{
		Entries: make([]apiclient.ProfileEntrySetting, 0, len(entries)),
	}
	for _, entry := range entries {
		setting := apiclient.ProfileEntrySetting{
			Id:   entry.ID,
			Mode: apiclient.ProfileEntrySettingMode(entry.Mode),
		}
		if entry.Version != "" {
			setting.Version = ptr(entry.Version)
		}
		body.Entries = append(body.Entries, setting)
	}

	resp, err := c.api.SetProfileEntriesWithResponse(ctx, slug, body)
	if err != nil {
		return ProfileDetail{}, fmt.Errorf("set the entries of %s: %w", slug, err)
	}
	if resp.JSON200 == nil {
		return ProfileDetail{}, profileFailure("set the entries of "+slug,
			resp.HTTPResponse, resp.Body)
	}
	return profileDetail(resp.JSON200), nil
}

// SetProfileSharing puts PUT /v1/profiles/{slug}/sharing: an UPSERT of
// roles, not a replacement — a subject the body does not name keeps its
// role. There is no way to remove one.
func (c *Client) SetProfileSharing(ctx context.Context, slug string, members []Share) (ProfileDetail, error) {
	if err := checkSlug(slug); err != nil {
		return ProfileDetail{}, err
	}

	body := apiclient.SetProfileSharingJSONRequestBody{
		Members: make([]apiclient.ProfileShare, 0, len(members)),
	}
	for _, member := range members {
		body.Members = append(body.Members, apiclient.ProfileShare{
			Kind: apiclient.ProfileShareKind(member.Kind),
			Ref:  member.Ref,
			Role: apiclient.ProfileShareRole(member.Role),
		})
	}

	resp, err := c.api.SetProfileSharingWithResponse(ctx, slug, body)
	if err != nil {
		return ProfileDetail{}, fmt.Errorf("set the sharing of %s: %w", slug, err)
	}
	if resp.JSON200 == nil {
		return ProfileDetail{}, profileFailure("set the sharing of "+slug,
			resp.HTTPResponse, resp.Body)
	}
	return profileDetail(resp.JSON200), nil
}

// SetProfileTargets puts PUT /v1/profiles/{slug}/targets — the enabled set
// in full. An omitted target is disabled; an empty list means the profile
// writes nothing until somebody chooses.
func (c *Client) SetProfileTargets(ctx context.Context, slug string, targets []string) (ProfileDetail, error) {
	if err := checkSlug(slug); err != nil {
		return ProfileDetail{}, err
	}

	body := apiclient.SetProfileTargetsJSONRequestBody{
		Targets: make([]apiclient.ProfileTargetSelectionTargets, 0, len(targets)),
	}
	for _, target := range targets {
		body.Targets = append(body.Targets, apiclient.ProfileTargetSelectionTargets(target))
	}

	resp, err := c.api.SetProfileTargetsWithResponse(ctx, slug, body)
	if err != nil {
		return ProfileDetail{}, fmt.Errorf("set the targets of %s: %w", slug, err)
	}
	if resp.JSON200 == nil {
		return ProfileDetail{}, profileFailure("set the targets of "+slug,
			resp.HTTPResponse, resp.Body)
	}
	return profileDetail(resp.JSON200), nil
}

// PublishRevision posts POST /v1/profiles/{slug}/revisions. The api's
// Location header is deliberately not carried: that is the API's URL space,
// which no browser on this role's origin may follow. A screen links to its
// own route and gets the number it needs from the body.
func (c *Client) PublishRevision(ctx context.Context, slug, note string) (PublishedRevision, error) {
	if err := checkSlug(slug); err != nil {
		return PublishedRevision{}, err
	}

	body := apiclient.PublishRevisionJSONRequestBody{}
	if note != "" {
		body.Note = &note
	}

	resp, err := c.api.PublishRevisionWithResponse(ctx, slug, body)
	if err != nil {
		return PublishedRevision{}, fmt.Errorf("publish a revision of %s: %w", slug, err)
	}
	if resp.JSON201 == nil {
		return PublishedRevision{}, profileFailure("publish a revision of "+slug,
			resp.HTTPResponse, resp.Body)
	}

	lockfile := resp.JSON201
	published := PublishedRevision{
		Revision:   int(lockfile.Revision),
		Note:       deref(lockfile.Note),
		ResolvedAt: lockfile.ResolvedAt,
		Gate:       string(lockfile.Gate),
		Entries:    make([]LockedEntry, 0, len(lockfile.Entries)),
		Skipped:    make([]Skip, 0, len(lockfile.Skipped)),
	}
	for i := range lockfile.Entries {
		entry := &lockfile.Entries[i]
		published.Entries = append(published.Entries, LockedEntry{
			ID:         entry.Id,
			Kind:       string(entry.Kind),
			Version:    entry.Version,
			Digest:     entry.Digest,
			Resolution: string(entry.Resolution),
			Verdict:    string(entry.Verdict),
			Override:   entryOverride(entry.Override),
		})
	}
	for _, skipped := range lockfile.Skipped {
		published.Skipped = append(published.Skipped, skip(skipped))
	}
	return published, nil
}

// checkSlug refuses an empty slug before it becomes a request: GET
// /v1/profiles/ carries none at all and gin answers with a 301 to
// /v1/profiles, which net/http follows and decodes as a blank ProfileDetail
// with no error at all.
func checkSlug(slug string) error {
	if slug == "" {
		return view.ErrNotFound
	}
	return nil
}

func profileDetail(body *apiclient.ProfileDetail) ProfileDetail {
	detail := ProfileDetail{
		Slug:               body.Slug,
		Name:               body.Name,
		Description:        deref(body.Description),
		Visibility:         string(body.Visibility),
		OwnerTeam:          deref(body.OwnerTeam),
		DefaultPolicy:      string(body.DefaultPolicy),
		Gate:               string(body.Gate),
		HeadRevision:       int(body.HeadRevision),
		ForkedFrom:         deref(body.ForkedFrom),
		UnpublishedChanges: body.UnpublishedChanges,
		Permissions: ProfilePermissions{
			Curate:  body.Permissions.Curate,
			Share:   body.Permissions.Share,
			Publish: body.Permissions.Publish,
		},
		Entries:   make([]ProfileEntry, 0, len(body.Entries)),
		Members:   make([]ProfileMember, 0, len(body.Members)),
		Targets:   make([]ProfileTarget, 0, len(body.Targets)),
		Revisions: make([]ProfileRevision, 0, len(body.Revisions)),
	}
	if body.Role != nil {
		detail.Role = string(*body.Role)
	}

	for i := range body.Entries {
		detail.Entries = append(detail.Entries, profileEntry(&body.Entries[i]))
	}
	for _, member := range body.Members {
		detail.Members = append(detail.Members, ProfileMember{
			Kind:        string(member.Kind),
			Ref:         member.Ref,
			Role:        string(member.Role),
			DisplayName: deref(member.DisplayName),
		})
	}
	for _, target := range body.Targets {
		detail.Targets = append(detail.Targets, ProfileTarget{
			Target: string(target.Target), Enabled: target.Enabled,
		})
	}
	for _, revision := range body.Revisions {
		detail.Revisions = append(detail.Revisions, ProfileRevision{
			Revision:    int(revision.Revision),
			Note:        deref(revision.Note),
			PublishedAt: revision.PublishedAt,
			PublishedBy: revision.PublishedBy,
		})
	}
	return detail
}

func profileEntry(from *apiclient.ProfileEntry) ProfileEntry {
	entry := ProfileEntry{
		ID:            from.Id,
		Name:          from.Name,
		Kind:          string(from.Kind),
		Mode:          string(from.Mode),
		Range:         deref(from.Range),
		PinnedVersion: deref(from.PinnedVersion),
		LatestVersion: deref(from.LatestVersion),
		Version:       deref(from.Version),
		Digest:        deref(from.Digest),
		Outcome:       string(from.Outcome),
		Note:          deref(from.Note),
		Override:      entryOverride(from.Override),
		Unpublished:   from.Unpublished,
	}
	if from.LatestVerdict != nil {
		entry.LatestVerdict = string(*from.LatestVerdict)
	}
	if from.Verdict != nil {
		entry.Verdict = string(*from.Verdict)
	}
	if from.Skip != nil {
		excluded := skip(*from.Skip)
		entry.Skip = &excluded
	}
	return entry
}

func skip(from apiclient.LockfileSkip) Skip {
	return Skip{
		ID:                  from.Id,
		Reason:              string(from.Reason),
		Detail:              deref(from.Detail),
		WouldHaveResolvedTo: deref(from.WouldHaveResolvedTo),
	}
}

func entryOverride(from *apiclient.LockfileOverride) *EntryOverride {
	if from == nil {
		return nil
	}
	out := &EntryOverride{Reviewer: from.Reviewer, Note: from.Note}
	if !from.ExpiresAt.IsZero() {
		expires := from.ExpiresAt
		out.ExpiresAt = &expires
	}
	return out
}

// profileFailure names the operation that failed, EXCEPT the not-found
// state, which travels bare: it is a screen rather than a failure.
func profileFailure(what string, resp *http.Response, body []byte) error {
	err := profileError(resp, body)
	if errors.Is(err, view.ErrNotFound) {
		return err
	}
	return fmt.Errorf("%s: %w", what, err)
}

// profileError adds the two answers a curation screen has to READ to
// governanceError's 401 and 403. A 404 is view.ErrNotFound and never a
// message about permission: guessing which it was would leak the existence
// of private profiles.
func profileError(resp *http.Response, body []byte) error {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return view.ErrNotFound
		case http.StatusConflict, http.StatusUnprocessableEntity:
			return &ProfileRefusedError{Detail: refusalDetail(body, resp)}
		}
	}
	return governanceError(resp, body)
}

// refusalDetail reads the api's RFC 9457 problem detail and falls back to a
// sentence of its own rather than the raw body: an undecodable body would
// put an unbounded upstream string in front of a browser.
func refusalDetail(body []byte, resp *http.Response) string {
	var problem apiclient.Error
	if err := json.Unmarshal(body, &problem); err == nil && problem.Detail != nil && *problem.Detail != "" {
		return *problem.Detail
	}
	return fmt.Sprintf("the hub refused this change (%s)", http.StatusText(resp.StatusCode))
}

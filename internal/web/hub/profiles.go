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

// The profile screen's door to the api (001 US5, T078-T084), through the
// generated client and nothing else.
//
// The shapes below live in THIS package for the reason governance.go states: they
// are what the api answers, mapped once into Go a screen can use, and the screen
// owns its own view models. Nothing here renders — no relative dates, no collapsed
// pills, no sentence composed out of an outcome — because deciding what a gate
// outcome MEANS is the resolver's job and deciding how it READS is the screen's.
//
// Three refusals, three different screens, and this package's whole job on the
// error path is keeping them apart. 401 is signed out. 403 is a role that may not
// do this (ErrForbidden, FR-126). 404 is a profile that either does not exist or
// is not readable by this identity, which the api answers identically on purpose
// (FR-044) and which this package must not try to tell apart. A 409 or a 422 is
// none of those: the caller is permitted and the api understood them, and the
// answer is a sentence a person has to read, so it arrives as ProfileRefusedError
// carrying that sentence. Everything else is the api being unreachable or broken,
// which the caller renders as a bad gateway.
//
// Note, Skip.Detail and a member's DisplayName quote content this hub did not
// write — a path out of a package bundle, a name out of the identity provider.
// Render them escaped, always (FR-055).

// ProfileRefusedError is the api refusing a curation request it understood from a
// caller it permitted: the slug is taken, the body leaves out a package the
// profile holds, the change would leave the profile with no owner.
//
// It carries the api's own sentence because the sentence IS the answer. Every one
// of these refusals exists to name the thing that was wrong — which package was
// omitted, which subject was named twice — and a screen that replaced it with
// wording of its own would be a second, worse copy of a rule it does not enforce.
type ProfileRefusedError struct {
	// Detail is the api's RFC 9457 problem detail. It quotes what the caller sent:
	// render it escaped (FR-055).
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
	// Gate is the org gate in force NOW, which is what Entries were resolved
	// under. It is not the gate the head revision froze; the two disagreeing is
	// part of what UnpublishedChanges reports.
	Gate         string
	HeadRevision int
	// ForkedFrom is lineage and nothing else: a fork never inherits the upstream's
	// later revisions (FR-038).
	ForkedFrom string

	// Role is legitimately empty. A profile with organisation visibility is
	// readable by everyone (FR-044) and most of those readers hold no membership,
	// so "no role" is a state and not a missing value.
	Role        string
	Permissions ProfilePermissions

	UnpublishedChanges bool

	Entries   []ProfileEntry
	Members   []ProfileMember
	Targets   []ProfileTarget
	Revisions []ProfileRevision
}

// ProfilePermissions is the api's answer to what this identity may do here, so a
// screen can disable a control rather than offer one that will be refused
// (FR-126). It is the screen's copy of the answer and never the mechanism: the
// operations enforce this themselves and will refuse regardless of what a browser
// was shown.
type ProfilePermissions struct {
	Curate  bool
	Share   bool
	Publish bool
}

// ProfileEntry is one package in a profile, with two version pairs that answer
// different questions. LatestVersion / LatestVerdict are the CATALOG's newest
// offering and its scan state — the row's Scan badge, unaffected by what the gate
// then does. Version / Verdict are what the entry actually resolves to, and are
// empty exactly when it is excluded.
type ProfileEntry struct {
	ID   string
	Name string
	Kind string

	// Mode is the profile's setting, not a label for what happened to it: a pin
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
	// Skip is present exactly when Outcome is skipped. FR-036: an excluded package
	// is reported with its reason and never silently dropped, so a screen that
	// renders only the resolved rows is a screen that lies.
	Skip *Skip
	// Override is the ACTIVE acceptance that let a flagged version through.
	Override *EntryOverride

	// Unpublished says this row would resolve differently from the head revision's
	// lockfile — a pin somebody toggled, or the catalog moving under a floating
	// entry. Either way no machine has seen it (001 US5 scenario 1).
	Unpublished bool
}

// Skip is one excluded package and why (FR-036). Reason is the canonical code and
// Detail is the resolver's prose about the finding that caused it.
type Skip struct {
	ID                  string
	Reason              string
	Detail              string
	WouldHaveResolvedTo string
}

// EntryOverride is the acceptance a flagged version resolved under.
//
// It is a type of its own rather than governance.go's Override because it is a
// different fact: that one is the decision as the scanner screen records it, with
// who decided and when. This is what the resolver applied, and the only date on it
// is when it lapses.
type EntryOverride struct {
	Reviewer string
	Note     string
	// ExpiresAt is nil when the acceptance does not lapse.
	//
	// The api's wire shape cannot say that: resolve.Override models "no expiry" as
	// a nil pointer and the lockfile schema requires `expiresAt`, so the two meet
	// at the ZERO instant. A screen handed that would render an override that never
	// expires as one that expired in the year 1 — so the zero instant is turned
	// back into the absence it stands for here, at the door, rather than in every
	// screen that formats a date.
	ExpiresAt *time.Time
}

// ProfileMember is one subject the profile is shared with (FR-037). A group is
// matched against the identity provider's claim on every request rather than
// expanded into people, which is why Kind travels.
type ProfileMember struct {
	Kind string
	Ref  string
	Role string
	// DisplayName is empty for a membership naming somebody this hub has never
	// seen sign in.
	DisplayName string
}

// ProfileTarget is one agent directory convention and whether this profile
// enables it. The api answers with the WHOLE vocabulary so a screen draws the same
// checkboxes without holding a copy of the enum.
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

// ProfileCreation is the create form. Every optional field is omitted from the
// request when it is empty, which is what makes the api's defaults apply — a new
// profile is private and floating-latest unless somebody said otherwise, and those
// defaults are the api's to hold. Sending an empty string instead would not be a
// polite way of saying nothing: it is outside every one of those enums and would
// be refused.
type ProfileCreation struct {
	Slug string
	Name string

	Description   string
	Visibility    string
	OwnerTeam     string
	DefaultPolicy string
	// ForkOf copies the named profile's entries as they stand now, and records
	// lineage only (FR-038).
	ForkOf string
}

// EntrySetting is one package's version policy. Version carries the pin or the
// range depending on Mode and is unused for latest — one field because exactly one
// of them is ever meaningful.
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

// PublishedRevision is what a publish froze (001 US5 scenario 5, FR-033).
//
// Deliberately not the whole lockfile. The bundle object keys and the signature
// refs are in it and no screen may show either: an object key is the CLI's
// business, and `verified` is false until FR-048a ships, so a signature panel
// today could only render provenance nobody checked. What is here is what the
// confirmation states — the number the caller could not choose, what it froze, and
// what it left out.
type PublishedRevision struct {
	// Revision is the number the SERVER allocated. There is no field in which to
	// ask for one and a concurrent publish may hold the one the caller expected, so
	// this is the only place a screen may learn it.
	Revision   int
	Note       string
	ResolvedAt time.Time
	Gate       string
	Entries    []LockedEntry
	// Skipped is FR-036 at publish time: a revision that excluded a package says
	// so, and a screen must report it rather than announce a clean publish.
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

// SetProfileEntries puts PUT /v1/profiles/{slug}/entries — the WHOLE ordered set,
// because position is what an ordered set means (FR-032) and a patch cannot
// express a reorder.
//
// A caller that means "this profile holds nothing" must pass an empty slice and
// will be refused by the api naming every package it left out, which is the
// intended answer: there is no removal, on this path or any other.
func (c *Client) SetProfileEntries(ctx context.Context, slug string, entries []EntrySetting) (ProfileDetail, error) {
	if err := checkSlug(slug); err != nil {
		return ProfileDetail{}, err
	}

	// Built with a length rather than left nil so an empty set is sent as `[]`. A
	// nil slice marshals to `null`, which is not an empty array to a validator and
	// would be refused as a malformed body rather than answered.
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

// SetProfileSharing puts PUT /v1/profiles/{slug}/sharing.
//
// An UPSERT of roles and not a replacement of the membership set: a subject the
// body does not name keeps the role it holds. There is no way to remove one, so a
// screen offering a remove control would be offering something no operation can
// serve.
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

// SetProfileTargets puts PUT /v1/profiles/{slug}/targets — the enabled set in
// full. An omitted target is disabled, and an empty list is legal: it means the
// profile writes nothing until somebody chooses (FR-039).
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

// PublishRevision posts POST /v1/profiles/{slug}/revisions.
//
// The api answers with a Location header naming the revision, and it is
// deliberately not carried: that is the API's path, in the API's URL space, which
// no browser on this role's origin may follow. A screen links to its own route and
// gets the number it needs from the body.
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

// checkSlug refuses the one slug that is not a profile before it becomes a
// request, for the reason the finding id's uuid check exists: it reaches these
// methods out of a URL a person can edit.
//
// The empty one is not merely useless, it is dangerous. GET /v1/profiles/ carries
// no slug at all, and gin answers it with a 301 to /v1/profiles — measured against
// the api's own router — which net/http follows, so the client would decode the
// LIST of every readable profile into a ProfileDetail. Every field it wants is
// absent from that body, encoding/json ignores what it does not recognise, and the
// screen would be handed a blank profile and no error at all.
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

// profileFailure names the operation that failed, EXCEPT when what came back is
// the not-found state. That one travels bare, the way Package and Finding hand it
// back: it is a screen rather than a failure, and "get profile example/x: no such
// package" is a log line that reads like a fault and names the wrong noun.
func profileFailure(what string, resp *http.Response, body []byte) error {
	err := profileError(resp, body)
	if errors.Is(err, view.ErrNotFound) {
		return err
	}
	return fmt.Errorf("%s: %w", what, err)
}

// profileError adds the two answers a curation screen has to READ to
// governanceError's 401 and 403.
//
// A 404 is view.ErrNotFound and never a message about permission: FR-044 makes an
// unreadable profile answer exactly as a missing one, and a door that guessed
// which it was would leak the existence of private profiles that the api went out
// of its way not to.
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

// refusalDetail reads the api's RFC 9457 problem detail, and falls back to a
// sentence of its own rather than to the raw body: an undecodable body is the api
// misbehaving, and echoing it would put an unbounded upstream string in front of a
// browser. Same reading detailOf uses on the registration path.
func refusalDetail(body []byte, resp *http.Response) string {
	var problem apiclient.Error
	if err := json.Unmarshal(body, &problem); err == nil && problem.Detail != nil && *problem.Detail != "" {
		return *problem.Detail
	}
	return fmt.Sprintf("the hub refused this change (%s)", http.StatusText(resp.StatusCode))
}

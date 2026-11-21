package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// Profile refusals map to screens: 401 signed out, 403 role, 404 missing or
// unreadable (deliberately indistinguishable), 409/422 ProfileRefusedError with
// the api's sentence, anything else a bad gateway.

// ProfileRefusedError is the api refusing a curation request it understood from a
// permitted caller; the api's sentence is the answer.
type ProfileRefusedError struct {
	// Detail quotes what the caller sent, so render it escaped.
	Detail string
}

func (e *ProfileRefusedError) Error() string { return e.Detail }

// ProfileCreation is the create form. Empty optional fields are omitted so the
// api's defaults apply; an empty string would fall outside every enum.
type ProfileCreation struct {
	Slug string
	Name string

	Description   string
	Visibility    string
	OwnerTeam     string
	DefaultPolicy string
	// ForkOf copies the named profile's current entries and records lineage only.
	ForkOf string
}

// EntrySetting is one package's version policy; Version is unused for latest.
type EntrySetting struct {
	ID      string
	Mode    string
	Version string
}

type Share struct {
	Kind string
	Ref  string
	Role string
}

// Profiles lists exactly the profiles this identity may read.
func (c *Client) Profiles(ctx context.Context) ([]view.ProfileRow, error) {
	resp, err := c.api.ListProfilesWithResponse(ctx)
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	if resp.JSON200 == nil {
		return nil, fmt.Errorf("list profiles: %w", governanceError(resp.HTTPResponse, resp.Body))
	}

	out := make([]view.ProfileRow, 0, len(resp.JSON200.Profiles))
	for i := range resp.JSON200.Profiles {
		out = append(out, profileRow(&resp.JSON200.Profiles[i]))
	}
	return out, nil
}

func (c *Client) Profile(ctx context.Context, slug string) (view.Profile, error) {
	if err := checkSlug(slug); err != nil {
		return view.Profile{}, err
	}

	resp, err := c.api.GetProfileWithResponse(ctx, slug)
	if err != nil {
		return view.Profile{}, fmt.Errorf("get profile %s: %w", slug, err)
	}
	if resp.JSON200 == nil {
		return view.Profile{}, profileFailure("get profile "+slug, resp.HTTPResponse, resp.Body)
	}
	return profileScreen(resp.JSON200), nil
}

func (c *Client) CreateProfile(ctx context.Context, creation ProfileCreation) (view.ProfileRow, error) {
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
		return view.ProfileRow{}, fmt.Errorf("create profile %s: %w", creation.Slug, err)
	}
	if resp.JSON201 == nil {
		return view.ProfileRow{}, profileFailure("create profile "+creation.Slug,
			resp.HTTPResponse, resp.Body)
	}

	return profileRow(resp.JSON201), nil
}

func profileRow(from *apiclient.Profile) view.ProfileRow {
	row := view.ProfileRow{
		Slug:         from.Slug,
		Name:         from.Name,
		PackageCount: int(from.PackageCount),
		HeadRevision: int(from.HeadRevision),
		CanCurate:    from.CanCurate,
	}
	if from.Visibility != nil {
		row.Visibility = string(*from.Visibility)
	}
	return row
}

// SetProfileEntries replaces the whole ordered set, since a patch cannot express
// a reorder. The api refuses a set that drops held packages, to catch stale
// clients; RemoveProfileEntry is the addressed removal.
func (c *Client) SetProfileEntries(ctx context.Context, slug string, entries []EntrySetting) (view.Profile, error) {
	if err := checkSlug(slug); err != nil {
		return view.Profile{}, err
	}

	// Non-nil so an empty set marshals as `[]`, not `null`.
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
		return view.Profile{}, fmt.Errorf("set the entries of %s: %w", slug, err)
	}
	if resp.JSON200 == nil {
		return view.Profile{}, profileFailure("set the entries of "+slug,
			resp.HTTPResponse, resp.Body)
	}
	return profileScreen(resp.JSON200), nil
}

// RemoveProfileEntry removes one entry, which SetProfileEntries cannot do.
func (c *Client) RemoveProfileEntry(ctx context.Context, slug, id string) (view.Profile, error) {
	if err := checkSlug(slug); err != nil {
		return view.Profile{}, err
	}

	resp, err := c.api.RemoveProfileEntryWithResponse(ctx, slug, apiclient.ProfileEntryRemoval{Id: id})
	if err != nil {
		return view.Profile{}, fmt.Errorf("remove %s from %s: %w", id, slug, err)
	}
	if resp.JSON200 == nil {
		return view.Profile{}, profileFailure("remove "+id+" from "+slug,
			resp.HTTPResponse, resp.Body)
	}
	return profileScreen(resp.JSON200), nil
}

// DeleteProfile refuses with a 409 (as ProfileRefusedError) when the profile holds
// a published revision, since a client may already have synced it.
func (c *Client) DeleteProfile(ctx context.Context, slug string) error {
	if err := checkSlug(slug); err != nil {
		return err
	}

	resp, err := c.api.DeleteProfileWithResponse(ctx, slug)
	if err != nil {
		return fmt.Errorf("delete profile %s: %w", slug, err)
	}
	if resp.HTTPResponse != nil && resp.HTTPResponse.StatusCode == http.StatusNoContent {
		return nil
	}
	return profileFailure("delete profile "+slug, resp.HTTPResponse, resp.Body)
}

// SetProfileSharing upserts roles; a subject the body omits keeps its role, and
// there is no way to remove one.
func (c *Client) SetProfileSharing(ctx context.Context, slug string, members []Share) (view.Profile, error) {
	if err := checkSlug(slug); err != nil {
		return view.Profile{}, err
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
		return view.Profile{}, fmt.Errorf("set the sharing of %s: %w", slug, err)
	}
	if resp.JSON200 == nil {
		return view.Profile{}, profileFailure("set the sharing of "+slug,
			resp.HTTPResponse, resp.Body)
	}
	return profileScreen(resp.JSON200), nil
}

// SetProfileTargets replaces the enabled set; an empty list writes nothing.
func (c *Client) SetProfileTargets(ctx context.Context, slug string, targets []string) (view.Profile, error) {
	if err := checkSlug(slug); err != nil {
		return view.Profile{}, err
	}

	body := apiclient.SetProfileTargetsJSONRequestBody{
		Targets: make([]apiclient.ProfileTargetSelectionTargets, 0, len(targets)),
	}
	for _, target := range targets {
		body.Targets = append(body.Targets, apiclient.ProfileTargetSelectionTargets(target))
	}

	resp, err := c.api.SetProfileTargetsWithResponse(ctx, slug, body)
	if err != nil {
		return view.Profile{}, fmt.Errorf("set the targets of %s: %w", slug, err)
	}
	if resp.JSON200 == nil {
		return view.Profile{}, profileFailure("set the targets of "+slug,
			resp.HTTPResponse, resp.Body)
	}
	return profileScreen(resp.JSON200), nil
}

// PublishRevision publishes a revision; the returned lockfile is not read.
func (c *Client) PublishRevision(ctx context.Context, slug, note string) error {
	if err := checkSlug(slug); err != nil {
		return err
	}

	body := apiclient.PublishRevisionJSONRequestBody{}
	if note != "" {
		body.Note = &note
	}

	resp, err := c.api.PublishRevisionWithResponse(ctx, slug, body)
	if err != nil {
		return fmt.Errorf("publish a revision of %s: %w", slug, err)
	}
	if resp.JSON201 == nil {
		return profileFailure("publish a revision of "+slug,
			resp.HTTPResponse, resp.Body)
	}
	return nil
}

// Revision reads one published revision as frozen. The diff panel compares two of
// these rather than a stored delta, so it can never drift from the lockfiles.
func (c *Client) Revision(ctx context.Context, slug string, revision int) (view.LockfileSnapshot, error) {
	if err := checkSlug(slug); err != nil {
		return view.LockfileSnapshot{}, err
	}

	resp, err := c.api.GetRevisionWithResponse(ctx, slug, strconv.Itoa(revision))
	if err != nil {
		return view.LockfileSnapshot{}, fmt.Errorf("get revision %d of %s: %w", revision, slug, err)
	}
	if resp.JSON200 == nil {
		return view.LockfileSnapshot{}, profileFailure(fmt.Sprintf("get revision %d of %s", revision, slug),
			resp.HTTPResponse, resp.Body)
	}
	return lockfileSnapshot(resp.JSON200), nil
}

func lockfileSnapshot(from *apiclient.Lockfile) view.LockfileSnapshot {
	out := view.LockfileSnapshot{
		Revision: int(from.Revision),
		Gate:     string(from.Gate),
		Entries:  make([]view.LockfileEntrySnapshot, 0, len(from.Entries)),
		Skipped:  make([]view.LockfileSkipSnapshot, 0, len(from.Skipped)),
	}
	if from.DefaultPolicy != nil {
		out.DefaultPolicy = string(*from.DefaultPolicy)
	}
	for _, target := range from.Targets {
		out.Targets = append(out.Targets, string(target))
	}
	for i := range from.Entries {
		entry := &from.Entries[i]
		out.Entries = append(out.Entries, view.LockfileEntrySnapshot{
			ID:         entry.Id,
			Version:    entry.Version,
			Resolution: string(entry.Resolution),
		})
	}
	for _, skipped := range from.Skipped {
		out.Skipped = append(out.Skipped, view.LockfileSkipSnapshot{
			ID: skipped.Id, Reason: string(skipped.Reason),
		})
	}
	return out
}

// checkSlug refuses an empty slug: GET /v1/profiles/ gets a 301 that net/http
// follows and decodes as a blank ProfileDetail without error.
func checkSlug(slug string) error {
	if slug == "" {
		return view.ErrNotFound
	}
	return nil
}

func profileScreen(body *apiclient.ProfileDetail) view.Profile {
	out := view.Profile{
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
		Permissions: view.ProfilePermissions{
			Curate:  body.Permissions.Curate,
			Share:   body.Permissions.Share,
			Publish: body.Permissions.Publish,
			Delete:  body.Permissions.Delete,
		},
	}
	if body.Role != nil {
		out.Role = string(*body.Role)
	}

	for i := range body.Entries {
		out.Entries = append(out.Entries, profileEntry(&body.Entries[i]))
	}
	for _, member := range body.Members {
		out.Members = append(out.Members, view.ProfileMemberRow{
			Kind:        string(member.Kind),
			Ref:         member.Ref,
			Role:        string(member.Role),
			DisplayName: deref(member.DisplayName),
		})
	}
	for _, target := range body.Targets {
		out.Targets = append(out.Targets, view.ProfileTargetRow{
			Target: string(target.Target), Enabled: target.Enabled,
		})
	}
	for _, revision := range body.Revisions {
		out.Revisions = append(out.Revisions, view.ProfileRevisionRow{
			Revision:    int(revision.Revision),
			Note:        deref(revision.Note),
			PublishedAt: view.Timestamp(revision.PublishedAt),
			PublishedBy: revision.PublishedBy,
		})
	}
	return out
}

func profileEntry(from *apiclient.ProfileEntry) view.ProfileEntryRow {
	entry := view.ProfileEntryRow{
		ID:            from.Id,
		Name:          from.Name,
		Kind:          view.Kind(from.Kind),
		Mode:          string(from.Mode),
		Range:         deref(from.Range),
		PinnedVersion: deref(from.PinnedVersion),
		LatestVersion: deref(from.LatestVersion),
		Version:       deref(from.Version),
		Digest:        deref(from.Digest),
		Outcome:       view.ProfileOutcome(from.Outcome),
		Note:          deref(from.Note),
		Override:      lockfileOverride(from.Override),
		Unpublished:   from.Unpublished,
	}
	if from.LatestVerdict != nil {
		entry.LatestVerdict = view.Verdict(*from.LatestVerdict)
	}
	if from.Verdict != nil {
		entry.Verdict = view.Verdict(*from.Verdict)
	}
	if from.Skip != nil {
		entry.Skip = &view.ProfileSkip{
			Reason:              string(from.Skip.Reason),
			Detail:              deref(from.Skip.Detail),
			WouldHaveResolvedTo: deref(from.Skip.WouldHaveResolvedTo),
		}
	}
	return entry
}

// lockfileOverride turns the schema's zero-instant "no expiry" back into absence.
func lockfileOverride(from *apiclient.LockfileOverride) *view.ProfileOverride {
	if from == nil {
		return nil
	}
	out := &view.ProfileOverride{Reviewer: from.Reviewer, Note: from.Note}
	if !from.ExpiresAt.IsZero() {
		out.Expires = view.Timestamp(from.ExpiresAt)
	}
	return out
}

// profileFailure wraps the operation name, except not-found, which is a screen.
func profileFailure(what string, resp *http.Response, body []byte) error {
	err := profileError(resp, body)
	if errors.Is(err, view.ErrNotFound) {
		return err
	}
	return fmt.Errorf("%s: %w", what, err)
}

// profileError extends governanceError with 404 and 409/422. A 404 never becomes a
// permission message: guessing would leak private profiles' existence.
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

// refusalDetail falls back to its own sentence rather than the raw body, which
// could put an unbounded upstream string in front of a browser.
func refusalDetail(body []byte, resp *http.Response) string {
	var problem apiclient.Error
	if err := json.Unmarshal(body, &problem); err == nil && problem.Detail != nil && *problem.Detail != "" {
		return *problem.Detail
	}
	return fmt.Sprintf("the hub refused this change (%s)", http.StatusText(resp.StatusCode))
}

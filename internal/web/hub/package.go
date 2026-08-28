package hub

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"agent-manager/internal/apiclient"
	"agent-manager/internal/web/view"
)

// The package detail screen's door to the api (US3), through the generated
// client and nothing else.

// Package implements web.PackageSource against GET /v1/packages/{namespace}/{name}.
//
// A 404 becomes view.ErrNotFound rather than an error to log: a package that
// does not exist and a package this identity may not read are the same answer by
// design, and both are a screen rather than a failure.
func (c *Client) Package(ctx context.Context, namespace, name string) (view.Package, error) {
	resp, err := c.api.GetPackageWithResponse(ctx, namespace, name)
	if err != nil {
		return view.Package{}, fmt.Errorf("get package %s/%s: %w", namespace, name, err)
	}
	if resp.JSON200 == nil {
		if resp.HTTPResponse != nil && resp.HTTPResponse.StatusCode == http.StatusNotFound {
			return view.Package{}, view.ErrNotFound
		}
		return view.Package{}, fmt.Errorf("get package %s/%s: %w", namespace, name,
			statusError(resp.HTTPResponse, resp.Body))
	}
	return packageDetail(resp.JSON200, c.now()), nil
}

func packageDetail(body *apiclient.PackageDetail, now time.Time) view.Package {
	detail := view.Package{
		ID:             body.Id,
		Name:           view.Title(body.Name),
		Kind:           view.Kind(body.Kind),
		Publisher:      body.Publisher.Slug,
		Verified:       body.Publisher.Verified,
		Version:        body.Version,
		Scan:           scanOf(string(body.Verdict)),
		Tags:           body.Tags,
		ManifestObject: string(body.ManifestObject),
		Manifest:       body.Manifest,
		SpecVersion:    deref(body.Origin.SpecVersion),
		ParentID:       deref(body.Origin.ParentId),
		ParentName:     deref(body.Origin.ParentName),
		Category:       deref(body.Category),
		Description:    deref(body.Description),
		Capabilities:   capabilities(body.Capabilities),
	}
	if detail.Tags == nil {
		detail.Tags = []string{}
	}

	for _, component := range body.Components {
		detail.Components = append(detail.Components, view.Component{
			Kind: string(component.Kind), Name: component.Name,
			Path: component.Path, Note: deref(component.Note),
		})
	}
	for i := range body.Versions {
		detail.Versions = append(detail.Versions, packageVersion(&body.Versions[i], now))
	}
	for _, dependent := range body.Dependents {
		detail.Dependents = append(detail.Dependents, view.Dependent{
			Slug: dependent.Slug, Name: dependent.Name, Mode: string(dependent.Mode),
			Pin: firstNonEmpty(deref(dependent.Version), deref(dependent.Range)),
		})
	}
	return detail
}

func packageVersion(v *apiclient.PackageVersion, now time.Time) view.PackageVersion {
	return view.PackageVersion{
		Version:   v.Version,
		DistTag:   string(v.DistTag),
		Scan:      scanOf(string(v.Verdict)),
		Date:      view.Relative(v.CreatedAt, now),
		ObjectKey: v.ObjectKey,
		Digest:    deref(v.Digest),
		Size:      humanSize(derefInt(v.SizeBytes)),
		PinnedBy:  int(v.PinnedBy),
	}
}

// capabilities merges the two lists into one row per capability name, which is
// what makes the panel a comparison rather than two lists a reader has to align
// by eye (T060). A name present on one side only still gets a row, because that
// asymmetry is the whole point of FR-027.
func capabilities(from apiclient.PackageCapabilities) view.Capabilities {
	rows := map[string]*view.CapabilityRow{}
	names := make([]string, 0, len(from.Inferred)+len(from.Expected))

	row := func(name string) *view.CapabilityRow {
		if existing, ok := rows[name]; ok {
			return existing
		}
		created := &view.CapabilityRow{Name: name}
		rows[name] = created
		names = append(names, name)
		return created
	}

	for _, inferred := range from.Inferred {
		row(string(inferred.Name)).Inferred = facet(inferred)
	}
	for _, expected := range from.Expected {
		row(string(expected.Name)).Expected = facet(expected)
	}

	// The api already orders each list by the capability vocabulary; merging two
	// of them cannot preserve that on its own, so the merged order is restated
	// here rather than left to map iteration.
	sort.SliceStable(names, func(i, j int) bool {
		return capabilityRank(names[i]) < capabilityRank(names[j])
	})

	out := view.Capabilities{Scanned: from.Scanned}
	for _, name := range names {
		out.Rows = append(out.Rows, *rows[name])
	}
	return out
}

// capabilityOrder is the panel's row order. It is spelled out rather than sorted
// alphabetically so `network` leads and `shell` — the one that is never below
// Review — is last, which is the order the design's rows read in.
var capabilityOrder = []string{"network", "filesystem.read", "filesystem.write", "shell"}

func capabilityRank(name string) int {
	for i, candidate := range capabilityOrder {
		if candidate == name {
			return i
		}
	}
	return len(capabilityOrder)
}

func facet(from apiclient.PackageCapability) view.CapabilityFacet {
	out := view.CapabilityFacet{
		Present:    true,
		Level:      string(from.Level),
		Detail:     from.Detail,
		Indefinite: from.Indefinite != nil && *from.Indefinite,
	}
	if out.Detail == nil {
		out.Detail = []string{}
	}
	return out
}

// humanSize renders a byte count the way the storage screen will. A version with
// no size yet — the fetch has not landed — renders as nothing rather than as
// "0 B", which would be a claim about an empty bundle.
func humanSize(bytes int64) string {
	switch {
	case bytes <= 0:
		return ""
	case bytes < 1024:
		return strconv.FormatInt(bytes, 10) + " B"
	case bytes < 1024*1024:
		return strconv.FormatFloat(float64(bytes)/1024, 'f', 1, 64) + " KB"
	default:
		return strconv.FormatFloat(float64(bytes)/(1024*1024), 'f', 1, 64) + " MB"
	}
}

func derefInt(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

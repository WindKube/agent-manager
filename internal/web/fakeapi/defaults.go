package fakeapi

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"agent-manager/internal/apiclient"
)

func (a *API) defaults(op string) http.HandlerFunc {
	d := a.Data
	switch op {
	case "getViewer":
		return func(w http.ResponseWriter, r *http.Request) {
			if d.Viewer == nil || !a.authorised(r) {
				Problem(w, http.StatusUnauthorized, "no session")
				return
			}
			JSON(w, http.StatusOK, d.Viewer)
		}
	case "createSession":
		return func(w http.ResponseWriter, _ *http.Request) { JSON(w, http.StatusOK, d.Session) }
	case "deleteSession", "deletePackage", "deleteProfile", "deleteGroupRoleMapping", "deleteCategory":
		return a.deletes(op)

	case "listPackages":
		return func(w http.ResponseWriter, r *http.Request) { JSON(w, http.StatusOK, d.catalog(r)) }
	case "getPackage":
		return keyed(d.Details, packageKey)
	case "listPackageFiles":
		return keyed(d.Files, packageKey)
	case "getPackageFile":
		return func(w http.ResponseWriter, r *http.Request) {
			file, ok := d.FileContents[packageKey(r)][r.URL.Query().Get("path")]
			if !ok {
				Problem(w, http.StatusNotFound, "no such file")
				return
			}
			JSON(w, http.StatusOK, file)
		}
	case "getPackageScan":
		return keyed(d.Scans, packageKey)
	case "previewPackage":
		return func(w http.ResponseWriter, _ *http.Request) { JSON(w, http.StatusOK, d.Preview) }
	case "registerPackage":
		return func(w http.ResponseWriter, _ *http.Request) { JSON(w, http.StatusAccepted, d.Registered) }
	case "deleteVersion":
		return func(w http.ResponseWriter, _ *http.Request) {
			JSON(w, http.StatusOK, apiclient.VersionDeleted{})
		}
	case "setPackageVisibility":
		return func(w http.ResponseWriter, r *http.Request) {
			var in apiclient.PackageVisibilityUpdate
			if !decode(w, r, &in) {
				return
			}
			detail, ok := d.Details[packageKey(r)]
			if !ok {
				Problem(w, http.StatusNotFound, "no such package")
				return
			}
			detail.Visibility = apiclient.PackageDetailVisibility(in.Visibility)
			d.Details[packageKey(r)] = detail
			JSON(w, http.StatusOK, detail)
		}
	case "setPackageTracking":
		return func(w http.ResponseWriter, r *http.Request) {
			var in apiclient.PackageTrackingUpdate
			if !decode(w, r, &in) {
				return
			}
			detail, ok := d.Details[packageKey(r)]
			if !ok {
				Problem(w, http.StatusNotFound, "no such package")
				return
			}
			if detail.Tracking == nil {
				Problem(w, http.StatusUnprocessableEntity, "not registered from git")
				return
			}
			tracking := *detail.Tracking
			tracking.TrackUpstream = in.TrackUpstream
			if in.TagPattern != nil {
				tracking.TagPattern = *in.TagPattern
			}
			detail.Tracking = &tracking
			d.Details[packageKey(r)] = detail
			JSON(w, http.StatusOK, detail)
		}

	case "listProfiles":
		return func(w http.ResponseWriter, _ *http.Request) {
			JSON(w, http.StatusOK, apiclient.ProfileList{Profiles: d.Profiles})
		}
	case "createProfile":
		return func(w http.ResponseWriter, r *http.Request) {
			var in apiclient.ProfileCreate
			if !decode(w, r, &in) {
				return
			}
			created := apiclient.Profile{Slug: in.Slug, Name: in.Name, CanCurate: true}
			d.Profiles = append(d.Profiles, created)
			JSON(w, http.StatusCreated, created)
		}
	case "getProfile", "setProfileEntries", "removeProfileEntry", "setProfileSharing", "setProfileTargets":
		return keyed(d.ProfileDetails, slug)
	case "publishRevision":
		return func(w http.ResponseWriter, r *http.Request) {
			detail, ok := d.ProfileDetails[slug(r)]
			if !ok {
				Problem(w, http.StatusNotFound, "no such profile")
				return
			}
			JSON(w, http.StatusCreated, d.Revisions[slug(r)][detail.HeadRevision])
		}
	case "getRevision":
		return func(w http.ResponseWriter, r *http.Request) {
			n, _ := strconv.ParseInt(r.PathValue("revision"), 10, 64)
			lockfile, ok := d.Revisions[slug(r)][n]
			if !ok {
				Problem(w, http.StatusNotFound, "no such revision")
				return
			}
			JSON(w, http.StatusOK, lockfile)
		}

	case "scannerSummary":
		return func(w http.ResponseWriter, _ *http.Request) { JSON(w, http.StatusOK, d.ScannerSummary) }
	case "listFindings":
		return func(w http.ResponseWriter, r *http.Request) { JSON(w, http.StatusOK, d.findings(r)) }
	case "getFinding":
		return keyed(d.FindingDetails, func(r *http.Request) string { return r.PathValue("id") })
	case "acceptFinding", "rejectFinding":
		return func(w http.ResponseWriter, _ *http.Request) { JSON(w, http.StatusOK, d.Decision) }
	case "listAudit":
		return func(w http.ResponseWriter, r *http.Request) {
			matched := d.audit(r)
			entries, page, size := paginate(matched, r, 50)
			JSON(w, http.StatusOK, apiclient.AuditPage{
				Entries: entries, Page: page, PageSize: size, Total: int64(len(matched)),
			})
		}
	case "exportAudit":
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/x-ndjson")
			if !auditFiltered(r) {
				_, _ = w.Write([]byte(d.AuditExport))
				return
			}
			_, _ = w.Write([]byte(auditExport(d.audit(r))))
		}
	case "getBadges":
		return func(w http.ResponseWriter, _ *http.Request) { JSON(w, http.StatusOK, d.Badges) }
	case "getStorage":
		return func(w http.ResponseWriter, _ *http.Request) { JSON(w, http.StatusOK, d.Storage) }
	case "getRuntime":
		return func(w http.ResponseWriter, _ *http.Request) { JSON(w, http.StatusOK, d.Runtime) }

	case "getOrganization":
		return func(w http.ResponseWriter, _ *http.Request) { JSON(w, http.StatusOK, d.Organization) }
	case "testIdentityConnection":
		return func(w http.ResponseWriter, _ *http.Request) { JSON(w, http.StatusOK, d.IdentityConnection) }
	case "updatePolicy":
		return func(w http.ResponseWriter, r *http.Request) {
			var in apiclient.UpdatePolicyRequest
			if !decode(w, r, &in) {
				return
			}
			d.Organization.Policy = apiclient.OrganizationPolicy{
				AllowPersonalProfiles: in.AllowPersonalProfiles,
				CommunityNeedsReview:  in.CommunityNeedsReview,
				RequireSignedBundles:  in.RequireSignedBundles,
				RescanOnNewVersion:    in.RescanOnNewVersion,
				ScanGate:              apiclient.OrganizationPolicyScanGate(in.ScanGate),
			}
			JSON(w, http.StatusOK, d.Organization.Policy)
		}
	case "createGroupRoleMapping":
		return func(w http.ResponseWriter, r *http.Request) {
			var in apiclient.CreateMappingRequest
			if !decode(w, r, &in) {
				return
			}
			mapping := apiclient.GroupRoleMapping{GroupName: in.GroupName, Role: apiclient.GroupRoleMappingRole(in.Role)}
			d.Organization.Mappings = append(d.Organization.Mappings, mapping)
			JSON(w, http.StatusOK, mapping)
		}
	case "createCategory", "updateCategory":
		return func(w http.ResponseWriter, r *http.Request) {
			var in apiclient.CreateCategoryRequest
			if !decode(w, r, &in) {
				return
			}
			id := uuid.New()
			if raw := r.PathValue("id"); raw != "" {
				id = uuid.MustParse(raw)
			}
			JSON(w, http.StatusOK, apiclient.OrganizationCategory{
				Id: id, Name: in.Name, Slug: strings.ToLower(strings.ReplaceAll(in.Name, " ", "-")),
			})
		}

	case "lookupDeviceCode":
		return keyed(d.Devices, func(r *http.Request) string { return r.PathValue("user_code") })
	case "approveDeviceCode":
		return func(w http.ResponseWriter, r *http.Request) {
			pending, ok := d.Devices[r.PathValue("user_code")]
			if !ok {
				Problem(w, http.StatusNotFound, "no such code")
				return
			}
			JSON(w, http.StatusOK, apiclient.ApprovedDeviceAuthorization{RequestingHost: pending.RequestingHost})
		}
	}
	panic("fakeapi: no default for " + op)
}

func (a *API) deletes(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d := a.Data
		switch op {
		case "deletePackage":
			JSON(w, http.StatusOK, apiclient.PackageDeleted{VersionsArchived: int64(len(d.Details[packageKey(r)].Versions))})
			return
		case "deleteProfile":
			d.Profiles = slices.DeleteFunc(d.Profiles, func(p apiclient.Profile) bool { return p.Slug == slug(r) })
			delete(d.ProfileDetails, slug(r))
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func keyed[T any](m map[string]T, key func(*http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, ok := m[key(r)]
		if !ok {
			Problem(w, http.StatusNotFound, "not found")
			return
		}
		JSON(w, http.StatusOK, v)
	}
}

func packageKey(r *http.Request) string { return r.PathValue("namespace") + "/" + r.PathValue("name") }

func slug(r *http.Request) string { return r.PathValue("slug") }

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		Problem(w, http.StatusUnprocessableEntity, err.Error())
		return false
	}
	return true
}

func paginate[T any](all []T, r *http.Request, defaultSize int64) (rows []T, page, size int64) {
	page = queryInt(r, "page", 1)
	size = queryInt(r, "pageSize", defaultSize)
	start := min((page-1)*size, int64(len(all)))
	end := min(start+size, int64(len(all)))
	return all[start:end], page, size
}

func queryInt(r *http.Request, name string, fallback int64) int64 {
	n, err := strconv.ParseInt(r.URL.Query().Get(name), 10, 64)
	if err != nil || n < 1 {
		return fallback
	}
	return n
}

func (d *Data) findings(r *http.Request) apiclient.FindingsPage {
	q := r.URL.Query()
	matched := make([]apiclient.FindingSummary, 0, len(d.Findings))
	for i := range d.Findings {
		f := &d.Findings[i]
		if state := q.Get("state"); state != "" && string(f.State) != state {
			continue
		}
		if severity := q.Get("severity"); severity != "" && string(f.Severity) != severity {
			continue
		}
		matched = append(matched, *f)
	}
	rows, page, size := paginate(matched, r, 20)
	return apiclient.FindingsPage{Findings: rows, Page: page, PageSize: size, Total: int64(len(matched))}
}

func auditFiltered(r *http.Request) bool {
	q := r.URL.Query()
	return q.Get("subjectKind") != "" || q.Get("namespace") != ""
}

// audit applies listAudit's filters the way the api does, including a package
// subject matching the rows about its versions and findings.
func (d *Data) audit(r *http.Request) []apiclient.AuditEntry {
	q := r.URL.Query()
	kind, id, namespace := q.Get("subjectKind"), q.Get("subjectId"), q.Get("namespace")
	matched := make([]apiclient.AuditEntry, 0, len(d.Audit))
	for i := range d.Audit {
		e := &d.Audit[i]
		entryKind, entryID := "", deref(e.SubjectId)
		if e.SubjectKind != nil {
			entryKind = string(*e.SubjectKind)
		}
		if kind != "" {
			match := entryKind == kind && (id == "" || entryID == id)
			if kind == "package" && id != "" && (entryKind == "version" || entryKind == "finding") && e.Data != nil {
				match = match || (*e.Data)["package"] == id
			}
			if !match {
				continue
			}
		}
		if namespace != "" && deref(e.Namespace) != namespace {
			continue
		}
		matched = append(matched, *e)
	}
	return matched
}

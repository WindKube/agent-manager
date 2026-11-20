package fakeapi

import "agent-manager/internal/apiclient"

// Data is what the fake answers reads with. Maps are keyed by
// "namespace/name" for packages, slug for profiles, id for findings.
type Data struct {
	// Viewer nil answers getViewer with 401: the signed-out state.
	Viewer *apiclient.Viewer
	// Session is what createSession mints.
	Session apiclient.Session

	Packages     []apiclient.CatalogPackage
	Categories   []string
	Details      map[string]apiclient.PackageDetail
	Files        map[string]apiclient.PackageFileList
	FileContents map[string]map[string]apiclient.PackageFileContent
	Scans        map[string]apiclient.PackageScan
	Preview      apiclient.PackagePreview
	Registered   apiclient.PackageRegistered

	ScannerSummary apiclient.ScannerSummary
	Findings       []apiclient.FindingSummary
	FindingDetails map[string]apiclient.FindingDetail
	Decision       apiclient.FindingDecision
	Audit          []apiclient.AuditEntry
	AuditExport    string
	Badges         apiclient.Badges

	Profiles       []apiclient.Profile
	ProfileDetails map[string]apiclient.ProfileDetail
	Revisions      map[string]map[int64]apiclient.Lockfile

	Organization       apiclient.Organization
	IdentityConnection apiclient.IdentityConnectionTest
	Storage            apiclient.StorageReport
	Runtime            apiclient.RuntimeReport
	Devices            map[string]apiclient.PendingDeviceAuthorization
	ServiceTokens      []apiclient.ServiceToken
	Machines           []apiclient.MachineDetail
}

// SignedOut clears the viewer, so every protected request lands on sign-in.
func (d *Data) SignedOut() { d.Viewer = nil }

// Unmapped makes the viewer signed in but holding no role.
func (d *Data) Unmapped() {
	d.Viewer = &apiclient.Viewer{
		DisplayName: "Bo Fixture",
		Email:       "bo@fixture.invalid",
		Groups:      []string{"contractors-eu"},
	}
}

// As makes the viewer hold role.
func (d *Data) As(role apiclient.ViewerRole) {
	v := signedIn()
	v.Role = &role
	d.Viewer = v
}

func signedIn() *apiclient.Viewer {
	role := apiclient.ViewerRole("catalog-admin")
	return &apiclient.Viewer{
		DisplayName: "Ada Fixture",
		Email:       "ada@fixture.invalid",
		Role:        &role,
		HasRole:     true,
		Groups:      []string{"eng-platform", "eng-all"},
	}
}

func (d *Data) viewerRef() string {
	if d.Viewer == nil {
		return ""
	}
	return d.Viewer.Email
}

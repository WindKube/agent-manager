package fakeapi

import (
	"time"

	"agent-manager/internal/apiclient"
)

// Seed is the design's dataset as the api would answer it: ten packages, four
// findings, two profiles, and the organisation, storage and runtime reports.
func Seed() *Data {
	now := time.Now().UTC()
	d := &Data{
		Viewer: signedIn(),
		Session: apiclient.Session{
			Token:     "fake-session-token",
			ExpiresAt: now.Add(12 * time.Hour),
			ExpiresIn: int64((12 * time.Hour).Seconds()),
		},
		Categories:         []string{"Infrastructure", "Security & compliance", "Data", "Developer workflow", "Documentation"},
		IdentityConnection: apiclient.IdentityConnectionTest{Ok: true},
		Devices:            map[string]apiclient.PendingDeviceAuthorization{},
	}
	seedCatalog(d, now)
	seedGovernance(d, now)
	seedProfiles(d, now)
	d.Organization = seedOrganization()
	d.Storage = seedStorage(now)
	d.Runtime = seedRuntime(now)
	return d
}

func ptr[T any](v T) *T { return &v }

func deref(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

package fakeapi

import (
	"time"

	"github.com/google/uuid"

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
		ServiceTokens: []apiclient.ServiceToken{{
			Id: uuid.MustParse("0193f2a0-0000-7000-8000-00000000c1c1"), Name: "release pipeline",
			Scopes: []string{"sync:profile/example/platform-engineer"}, CreatedBy: "ada@fixture.invalid",
			CreatedAt: now.Add(-30 * 24 * time.Hour), ExpiresAt: now.Add(60 * 24 * time.Hour),
			LastUsedAt: ptr(now.Add(-2 * time.Hour)), Status: apiclient.Active,
		}},
	}
	d.Machines = seedMachines(now)
	seedWebhooks(d, now)
	seedCatalog(d, now)
	seedGovernance(d, now)
	seedProfiles(d, now)
	d.Organization = seedOrganization()
	for id := range d.Details {
		if d.Details[id].Signer.Issuer == nil {
			d.Organization.Policy.PackagesWithoutExpectedSigner++
		}
	}
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

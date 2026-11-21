package notify_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/notify"
)

func TestTheAPIEnumIsEveryEventTypeAndTheWildcard(t *testing.T) {
	want := []string{notify.AllEvents}
	for _, et := range notify.EventTypes() {
		want = append(want, string(et))
	}
	require.ElementsMatch(t, want, strings.Split(notify.EventTypesEnum, ","))
}

func TestAuditRowsMapToEventTypes(t *testing.T) {
	for _, tc := range []struct {
		kind, action, subject string
		want                  notify.EventType
	}{
		{"scan", "scanned", "version", notify.ScanCompleted},
		{"fetch", "deleted", "version", notify.VersionDeleted},
		{"fetch", "deleted", "package", notify.PackageDeleted},
		{"approve", "waiver-expired", "finding", notify.WaiverExpired},
		{"token", "created", "service-token", notify.TokenCreated},
	} {
		got, ok := notify.FromAudit(tc.kind, tc.action, tc.subject)
		require.True(t, ok, "%s/%s", tc.kind, tc.action)
		require.Equal(t, tc.want, got)
	}

	for _, quiet := range [][3]string{
		{"login", "signed-in", "identity"},
		{"token", "used", "service-token"},
		{"webhook", "created", "webhook"},
		{"approve", "accepted", "version"},
	} {
		_, ok := notify.FromAudit(quiet[0], quiet[1], quiet[2])
		require.False(t, ok, "%v must raise no event", quiet)
	}
	require.NotContains(t, notify.AuditKinds(), "login")
	require.Contains(t, notify.AuditKinds(), "scan")
}

func TestASubscriptionFilterSelectsByTypeAndNamespace(t *testing.T) {
	require.True(t, notify.Matches([]string{"*"}, nil, notify.ScanCompleted, "platform"))
	require.True(t, notify.Matches([]string{"*"}, nil, notify.PolicyChanged, ""))
	require.True(t, notify.Matches([]string{"scan.completed"}, []string{"platform"}, notify.ScanCompleted, "platform"))
	require.False(t, notify.Matches([]string{"scan.completed"}, nil, notify.FindingAccepted, "platform"))
	require.False(t, notify.Matches([]string{"*"}, []string{"platform"}, notify.ScanCompleted, "other"))
	require.False(t, notify.Matches([]string{"*"}, []string{"platform"}, notify.PolicyChanged, ""),
		"a namespace filter excludes events that belong to no namespace")
}

func TestWebhookURLsMustBePublicHTTPS(t *testing.T) {
	for _, ok := range []string{
		"https://hooks.example.com/services/T0/B0/x",
		"https://8.8.8.8/hook",
		"https://example.com:8443/hook?team=platform",
	} {
		_, err := notify.ValidateURL(ok)
		require.NoError(t, err, ok)
	}
	for raw, why := range map[string]string{
		"http://hooks.example.com/x":           "only https",
		"https://user:pw@example.com/x":        "credentials",
		"https://example.com/x#frag":           "fragment",
		"https://localhost/x":                  "localhost",
		"https://api.localhost./x":             "localhost",
		"https://127.0.0.1/x":                  "loopback",
		"https://10.1.2.3/x":                   "private",
		"https://169.254.169.254/latest":       "link-local",
		"https://[::1]/x":                      "loopback",
		"https://[::ffff:192.168.1.1]/x":       "private",
		"https:///x":                           "no host",
		"ftp://example.com/x":                  "only https",
		"https://" + strings.Repeat("a", 2050): "characters",
	} {
		_, err := notify.ValidateURL(raw)
		require.ErrorIs(t, err, notify.ErrInvalidURL, raw)
		require.ErrorContains(t, err, why, raw)
	}
	require.Equal(t, "hooks.example.com", notify.RedactedHost("https://hooks.example.com/services/T0/B0/secret"))
}

func TestTheSignatureFollowsTheStandardWebhooksScheme(t *testing.T) {
	// The Standard Webhooks reference vector.
	key, err := notify.DecodeSecret("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
	require.NoError(t, err)
	body := []byte(`{"test": 2432232314}`)
	sig := notify.Sign(key, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, body)
	require.Equal(t, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=", sig)

	require.True(t, notify.Verify(key, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, body, "v1,bogus "+sig))
	require.False(t, notify.Verify(key, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265331, body, sig))

	fresh, err := notify.NewSecret()
	require.NoError(t, err)
	require.Len(t, fresh, notify.SecretSize)
	round, err := notify.DecodeSecret(notify.EncodeSecret(fresh))
	require.NoError(t, err)
	require.Equal(t, fresh, round)
}

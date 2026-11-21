// Package config holds one environment struct per role, so a role's struct
// can't contain a field it has no business reading.
package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
)

const EnvPrefix = "AGENT_MANAGER_"

type Observability struct {
	LogLevel    string `env:"LOG_LEVEL" envDefault:"info"`
	LogFormat   string `env:"LOG_FORMAT" envDefault:"json"`
	MetricsBind string `env:"METRICS_ADDR" envDefault:":9090"`
}

type OIDC struct {
	Issuer         string   `env:"OIDC_ISSUER"`
	DiscoveryURL   string   `env:"OIDC_DISCOVERY_URL"`
	BrowserBaseURL string   `env:"OIDC_BROWSER_BASE_URL"`
	ClientID       string   `env:"OIDC_CLIENT_ID"`
	ClientSecret   string   `env:"OIDC_CLIENT_SECRET"`
	RedirectURL    string   `env:"OIDC_REDIRECT_URL"`
	Scopes         []string `env:"OIDC_SCOPES" envSeparator:" " envDefault:"openid profile email groups"`
}

type API struct {
	Observability
	OIDC

	Addr                  string        `env:"API_ADDR" envDefault:":8081"`
	DatabaseURL           string        `env:"DATABASE_URL,required,notEmpty"`
	RiverDatabaseURL      string        `env:"RIVER_DATABASE_URL,required,notEmpty"`
	BlobURL               string        `env:"BLOB_URL,required,notEmpty"`
	SessionTTL            time.Duration `env:"SESSION_TTL" envDefault:"12h"`
	DeviceCodeTTL         time.Duration `env:"DEVICE_CODE_TTL" envDefault:"10m"`
	DeviceTokenTTL        time.Duration `env:"DEVICE_TOKEN_TTL" envDefault:"1h"`
	PublicBaseURL         string        `env:"PUBLIC_BASE_URL" envDefault:"http://localhost:8081"`
	DeviceVerificationURL string        `env:"DEVICE_VERIFICATION_URL" envDefault:"http://localhost:8080/cli"`
	// SessionMintSecret authenticates web asking the API to mint a session. It
	// has no default, since a default would be a secret every deployment knows;
	// empty means the mint is refused.
	SessionMintSecret string `env:"SESSION_MINT_SECRET"`
	// BootstrapAdminGroup is the IdP group reconciled as catalog-admin on every
	// start. A fresh hub needs it because mapping groups to roles itself
	// requires catalog-admin. Empty reconciles nothing.
	BootstrapAdminGroup string `env:"BOOTSTRAP_ADMIN_GROUP"`
}

type Web struct {
	Observability
	OIDC

	Addr       string `env:"WEB_ADDR" envDefault:":8080"`
	APIBaseURL string `env:"API_BASE_URL,required,notEmpty"`
	// PublicBaseURL, not the request, decides whether session cookies are
	// Secure, since upstream TLS termination may forward plain http.
	PublicBaseURL     string `env:"PUBLIC_BASE_URL" envDefault:"http://localhost:8080"`
	SessionMintSecret string `env:"SESSION_MINT_SECRET"`
	// DevCredentialHint shows the local stack's seeded passwords on the sign-in
	// screen. It must be set explicitly, never inferred.
	DevCredentialHint bool   `env:"WEB_DEV_CREDENTIAL_HINT" envDefault:"false"`
	ProviderName      string `env:"WEB_PROVIDER_NAME"`
	HubURL            string `env:"WEB_HUB_URL" envDefault:"http://localhost:8081"`
	// RiverUIURL is River's queue dashboard; empty shows its entry disabled.
	// The dashboard holds the queue credential, this role holds none.
	RiverUIURL string `env:"RIVER_UI_URL"`
	// CookieKey is base64 of at least 32 bytes signing the sign-in round-trip
	// cookie. Every replica must share it; empty draws a per-process key.
	CookieKey string `env:"WEB_COOKIE_KEY"`
}

type Fetcher struct {
	Observability

	DatabaseURL      string        `env:"DATABASE_URL,required,notEmpty"`
	RiverDatabaseURL string        `env:"RIVER_DATABASE_URL,required,notEmpty"`
	BlobURL          string        `env:"BLOB_URL,required,notEmpty"`
	FetchTimeout     time.Duration `env:"FETCH_TIMEOUT" envDefault:"60s"`
	// OutboundAllowlist takes addresses only (`ip`, `ip:port` or CIDR); a
	// hostname would reopen the DNS-rebinding hole internal/fetch closes.
	OutboundAllowlist []string `env:"OUTBOUND_ALLOWLIST" envSeparator:","`
	MaxUploadBytes    int64    `env:"MAX_UPLOAD_BYTES" envDefault:"26214400"`
	GitHubToken       string   `env:"GITHUB_TOKEN"`
	// SigstoreTrustedRoot is a path to a trusted_root.json. Empty uses the
	// public-good root via TUF, refreshed daily.
	SigstoreTrustedRoot string        `env:"SIGSTORE_TRUSTED_ROOT"`
	UpstreamInterval    time.Duration `env:"UPSTREAM_INTERVAL" envDefault:"1h"`
}

// MinUpstreamInterval keeps the upstream check under forge rate limits.
const MinUpstreamInterval = 5 * time.Minute

func CheckUpstreamInterval(d time.Duration) error {
	if d < MinUpstreamInterval {
		return fmt.Errorf("%sUPSTREAM_INTERVAL is %s; it must be at least %s", EnvPrefix, d, MinUpstreamInterval)
	}
	return nil
}

type Scanner struct {
	Observability

	DatabaseURL      string        `env:"DATABASE_URL,required,notEmpty"`
	RiverDatabaseURL string        `env:"RIVER_DATABASE_URL,required,notEmpty"`
	BlobURL          string        `env:"BLOB_URL,required,notEmpty"`
	RulepackDir      string        `env:"RULEPACK_DIR" envDefault:"/etc/agent-manager/rulepack"`
	ScanBudget       time.Duration `env:"SCAN_BUDGET" envDefault:"120s"`

	// ScanEngineURL is the second analysis engine; empty runs the rule pack alone.
	ScanEngineURL string `env:"SCAN_ENGINE_URL"`
	// ScanEngineRequired fails a version the engine could not analyse rather
	// than clearing it on the rule pack alone, so an outage cannot silently
	// narrow coverage.
	ScanEngineRequired bool          `env:"SCAN_ENGINE_REQUIRED" envDefault:"true"`
	ScanEngineTimeout  time.Duration `env:"SCAN_ENGINE_TIMEOUT" envDefault:"60s"`
	// ScanEnginePolicy is strict, balanced or permissive.
	ScanEnginePolicy string `env:"SCAN_ENGINE_POLICY" envDefault:"balanced"`
	// ScanEngineThreshold is the lowest severity stored as a finding; lower ones
	// are only counted, so skill-quality complaints do not flag a version.
	ScanEngineThreshold string `env:"SCAN_ENGINE_THRESHOLD" envDefault:"medium"`
}

// Notifier is the webhook role's own settings. It has no object-store field
// because the role holds no object-store credential.
type Notifier struct {
	WebhookTimeout           time.Duration `env:"WEBHOOK_TIMEOUT" envDefault:"10s"`
	WebhookDeliveryRetention time.Duration `env:"WEBHOOK_DELIVERY_RETENTION" envDefault:"720h"`
	// WebhookDispatchInterval is the floor of a webhook's latency.
	WebhookDispatchInterval time.Duration `env:"WEBHOOK_DISPATCH_INTERVAL" envDefault:"10s"`
	WaiverCheckInterval     time.Duration `env:"WAIVER_CHECK_INTERVAL" envDefault:"1h"`
	// WaiverNotice is how long before expiry waiver.expiring is raised.
	WaiverNotice time.Duration `env:"WAIVER_NOTICE" envDefault:"168h"`
}

type Migrate struct {
	Observability
	RiverDatabaseURL string `env:"RIVER_DATABASE_URL,required,notEmpty"`
}

type Seed struct {
	Observability
	DatabaseURL string `env:"DATABASE_URL,required,notEmpty"`
	BlobURL     string `env:"BLOB_URL,required,notEmpty"`
}

func Load[T any]() (T, error) {
	var cfg T
	if err := env.ParseWithOptions(&cfg, env.Options{Prefix: EnvPrefix}); err != nil {
		return cfg, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

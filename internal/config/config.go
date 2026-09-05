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
	// SessionMintSecret authenticates the one operation whose caller is a role
	// rather than a person: web asking for a session to be minted. It has no
	// default (a default would be a shared secret every deployment knows);
	// empty means the mint is refused.
	SessionMintSecret string `env:"SESSION_MINT_SECRET"`
}

type Web struct {
	Observability
	OIDC

	Addr       string `env:"WEB_ADDR" envDefault:":8080"`
	APIBaseURL string `env:"API_BASE_URL,required,notEmpty"`
	// PublicBaseURL is read INSTEAD of the request to decide whether session
	// cookies are marked Secure: something upstream may terminate TLS and
	// forward plain http, so a request alone could miss it.
	PublicBaseURL     string `env:"PUBLIC_BASE_URL" envDefault:"http://localhost:8080"`
	SessionMintSecret string `env:"SESSION_MINT_SECRET"`
	// DevCredentialHint puts the local stack's seeded passwords on the
	// sign-in screen. Must be stated explicitly, never derived from the
	// issuer URL, host name or build type.
	DevCredentialHint bool   `env:"WEB_DEV_CREDENTIAL_HINT" envDefault:"false"`
	ProviderName      string `env:"WEB_PROVIDER_NAME"`
	HubURL            string `env:"WEB_HUB_URL" envDefault:"http://localhost:8081"`
}

type Fetcher struct {
	Observability

	DatabaseURL      string        `env:"DATABASE_URL,required,notEmpty"`
	RiverDatabaseURL string        `env:"RIVER_DATABASE_URL,required,notEmpty"`
	BlobURL          string        `env:"BLOB_URL,required,notEmpty"`
	FetchTimeout     time.Duration `env:"FETCH_TIMEOUT" envDefault:"60s"`
	// OutboundAllowlist entries are addresses only (`ip`, `ip:port` or CIDR);
	// a hostname is refused because allowlisting a name would reopen the
	// DNS-rebinding hole internal/fetch exists to close.
	OutboundAllowlist []string `env:"OUTBOUND_ALLOWLIST" envSeparator:","`
	MaxUploadBytes    int64    `env:"MAX_UPLOAD_BYTES" envDefault:"26214400"`
	GitHubToken       string   `env:"GITHUB_TOKEN"`
}

type Scanner struct {
	Observability

	DatabaseURL      string        `env:"DATABASE_URL,required,notEmpty"`
	RiverDatabaseURL string        `env:"RIVER_DATABASE_URL,required,notEmpty"`
	BlobURL          string        `env:"BLOB_URL,required,notEmpty"`
	RulepackDir      string        `env:"RULEPACK_DIR" envDefault:"/etc/agent-manager/rulepack"`
	ScanBudget       time.Duration `env:"SCAN_BUDGET" envDefault:"120s"`
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

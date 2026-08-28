// Package config holds one environment struct per role.
//
// Constitution principle II: a role's struct MUST NOT contain a field it has no
// business reading. Web carries no DatabaseURL and no BlobURL — not an unused
// field, no field at all — so the credential boundary is visible in the type.
package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
)

const EnvPrefix = "AGENT_MANAGER_"

// Observability is shared by every role.
type Observability struct {
	LogLevel    string `env:"LOG_LEVEL" envDefault:"info"`
	LogFormat   string `env:"LOG_FORMAT" envDefault:"json"`
	MetricsBind string `env:"METRICS_ADDR" envDefault:":9090"`
}

// OIDC is held only by roles that authenticate people: api and web.
type OIDC struct {
	Issuer string `env:"OIDC_ISSUER"`
	// DiscoveryURL is where the discovery document is fetched from when that is
	// not the issuer — a container reaching a browser-facing issuer over the
	// compose network. Empty means the two are the same, which is the ordinary
	// case and the one a real IdP presents. See quickstart.md.
	DiscoveryURL string   `env:"OIDC_DISCOVERY_URL"`
	ClientID     string   `env:"OIDC_CLIENT_ID"`
	ClientSecret string   `env:"OIDC_CLIENT_SECRET"`
	RedirectURL  string   `env:"OIDC_REDIRECT_URL"`
	Scopes       []string `env:"OIDC_SCOPES" envSeparator:" " envDefault:"openid profile email groups"`
}

// API owns the relational schema and mediates every mutation. It also hosts the
// outbox relay (research R5), which is why it holds the river URL.
type API struct {
	Observability
	OIDC

	Addr             string        `env:"API_ADDR" envDefault:":8081"`
	DatabaseURL      string        `env:"DATABASE_URL,required,notEmpty"`
	RiverDatabaseURL string        `env:"RIVER_DATABASE_URL,required,notEmpty"`
	BlobURL          string        `env:"BLOB_URL,required,notEmpty"`
	SessionTTL       time.Duration `env:"SESSION_TTL" envDefault:"12h"`
	DeviceCodeTTL    time.Duration `env:"DEVICE_CODE_TTL" envDefault:"10m"`
	DeviceTokenTTL   time.Duration `env:"DEVICE_TOKEN_TTL" envDefault:"1h"`
	PublicBaseURL    string        `env:"PUBLIC_BASE_URL" envDefault:"http://localhost:8081"`
}

// Web reaches data only through the api role. It deliberately has no
// DatabaseURL and no BlobURL field.
type Web struct {
	Observability
	OIDC

	Addr       string `env:"WEB_ADDR" envDefault:":8080"`
	APIBaseURL string `env:"API_BASE_URL,required,notEmpty"`
}

// Fetcher is the only role with object-store write access.
type Fetcher struct {
	Observability

	DatabaseURL      string        `env:"DATABASE_URL,required,notEmpty"`
	RiverDatabaseURL string        `env:"RIVER_DATABASE_URL,required,notEmpty"`
	BlobURL          string        `env:"BLOB_URL,required,notEmpty"`
	FetchTimeout     time.Duration `env:"FETCH_TIMEOUT" envDefault:"60s"`
	// OutboundAllowlist exempts specific addresses from the reserved-range and
	// port rules. Entries are addresses only — `ip`, `ip:port` or CIDR. A
	// hostname is refused, because allowlisting a name reopens the DNS-rebinding
	// hole internal/fetch exists to close.
	OutboundAllowlist []string `env:"OUTBOUND_ALLOWLIST" envSeparator:","`
	MaxUploadBytes    int64    `env:"MAX_UPLOAD_BYTES" envDefault:"26214400"`
	GitHubToken       string   `env:"GITHUB_TOKEN"`
}

// Scanner reads bytes and writes verdicts. It never writes bundle bytes.
type Scanner struct {
	Observability

	DatabaseURL      string        `env:"DATABASE_URL,required,notEmpty"`
	RiverDatabaseURL string        `env:"RIVER_DATABASE_URL,required,notEmpty"`
	BlobURL          string        `env:"BLOB_URL,required,notEmpty"`
	RulepackDir      string        `env:"RULEPACK_DIR" envDefault:"/etc/agent-manager/rulepack"`
	ScanBudget       time.Duration `env:"SCAN_BUDGET" envDefault:"120s"`
}

// Migrate is used by the queue migrator subcommand only.
type Migrate struct {
	Observability
	RiverDatabaseURL string `env:"RIVER_DATABASE_URL,required,notEmpty"`
}

// Seed loads the design's dataset as a one-shot.
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

//go:build integration

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"agent-manager/internal/web/view"
)

// These tests check the compose.yaml / compose.infra.yaml split, which breaks
// silently at boot rather than at parse time. They only run `config`.

const (
	rootComposeFile  = "compose.yaml"
	infraComposeFile = "compose.infra.yaml"
)

func TestTheInfrastructureComposeFileIsAWholeProjectAlone(t *testing.T) {
	root := repoRootForCompose(t)
	requireDockerCLI(t)

	out, err := compose(t, root, "-f", infraComposeFile, "config")
	require.NoError(t, err, "compose.infra.yaml must parse and merge with no other file:\n%s", out)

	services, err := compose(t, root, "-f", infraComposeFile, "config", "--services")
	require.NoError(t, err, services)
	require.ElementsMatch(t,
		[]string{
			"postgres", "postgres-init", "minio", "minio-init", "dex", "glauth", "migrate",
			// Reads only the queue database, and is unprofiled so `up` on this file brings it.
			"queue-ui",
		},
		lines(services),
		"this is what infrastructure means")
}

func TestBothComposeFilesNameTheSameProject(t *testing.T) {
	root := repoRootForCompose(t)

	// Otherwise the roles land on a different network and cannot resolve `postgres`.
	// Raw keys, because Compose defaults the rendered name from the directory.
	app := declaredProjectName(t, root, rootComposeFile)
	require.NotEmpty(t, app, "%s declares no name, so it takes whatever the directory is called", rootComposeFile)
	require.Equal(t, app, declaredProjectName(t, root, infraComposeFile),
		"%s started alone would be a different project than `docker compose up`", infraComposeFile)
}

func TestTheArgumentFreeCommandStillSeesBothComposeFiles(t *testing.T) {
	root := repoRootForCompose(t)
	requireDockerCLI(t)

	// No -f and no profile: the single documented command.
	out, err := compose(t, root, "config", "--services")
	require.NoError(t, err, out)
	seen := lines(out)

	require.Contains(t, seen, "postgres", "compose.infra.yaml is not being included")
	require.Contains(t, seen, "api", "compose.yaml's own services are missing")

	// Every declared service is reachable, with all profiles enabled.
	profiles, err := compose(t, root, "config", "--profiles")
	require.NoError(t, err, profiles)

	args := []string{}
	for _, p := range lines(profiles) {
		args = append(args, "--profile", p)
	}
	all, err := compose(t, root, append(args, "config", "--services")...)
	require.NoError(t, err, all)

	require.ElementsMatch(t,
		union(declaredServices(t, root, rootComposeFile), declaredServices(t, root, infraComposeFile)),
		lines(all))
}

func TestNoServiceIsDeclaredInBothComposeFiles(t *testing.T) {
	root := repoRootForCompose(t)

	// Compose silently merges a service declared in both files, so only the raw keys can catch it.
	app := declaredServices(t, root, rootComposeFile)
	infra := declaredServices(t, root, infraComposeFile)

	var both []string
	for _, name := range app {
		if slices.Contains(infra, name) {
			both = append(both, name)
		}
	}
	require.Empty(t, both, "declared in both compose files, so one copy silently wins")
}

func TestNoTwoServicesClaimTheSameHostPort(t *testing.T) {
	root := repoRootForCompose(t)
	requireDockerCLI(t)

	// `config` accepts a duplicate host port; it only fails at `up`.
	profiles, err := compose(t, root, "config", "--profiles")
	require.NoError(t, err, profiles)

	for _, enabled := range profileCombinations(lines(profiles)) {
		t.Run(profileRunName(enabled), func(t *testing.T) {
			args := []string{}
			for _, p := range enabled {
				args = append(args, "--profile", p)
			}

			var doc struct {
				Services map[string]struct {
					Ports []struct {
						Published string `json:"published"`
						Protocol  string `json:"protocol"`
					} `json:"ports"`
				} `json:"services"`
			}
			raw := composeJSON(t, root, append(args, "config", "--format", "json")...)
			require.NoError(t, json.Unmarshal(raw, &doc))
			require.NotEmpty(t, doc.Services)

			claims := map[string][]string{}
			for name, service := range doc.Services {
				for _, port := range service.Ports {
					// Ephemeral host ports cannot collide.
					if port.Published == "" || port.Published == "0" {
						continue
					}

					key := port.Published + "/" + port.Protocol
					claims[key] = append(claims[key], name)
				}
			}

			var collisions []string
			for key, claimants := range claims {
				if len(claimants) > 1 {
					slices.Sort(claimants)
					collisions = append(collisions, key+" wanted by "+strings.Join(claimants, " and "))
				}
			}
			slices.Sort(collisions)

			require.Empty(t, collisions, "one host port, two services: `up` fails and `config` does not")
		})
	}
}

// The dashboard's PATH_PREFIX and the web role's embed prefix live in two places
// that cannot be derived from each other; this assertion is what keeps them equal.
func TestTheQueueDashboardIsServedUnderThePrefixTheWebRoleEmbedsIt(t *testing.T) {
	root := repoRootForCompose(t)
	requireDockerCLI(t)

	var doc struct {
		Services map[string]struct {
			Environment map[string]*string `json:"environment"`
		} `json:"services"`
	}
	require.NoError(t, json.Unmarshal(composeJSON(t, root, "config", "--format", "json"), &doc))

	queueUI, ok := doc.Services["queue-ui"]
	require.True(t, ok, "no queue-ui service, so this test is not checking anything")
	prefix := queueUI.Environment["PATH_PREFIX"]
	require.NotNil(t, prefix, "queue-ui serves at / without this, and the web role mounts it "+
		"under a prefix — every asset the frame asks for would 404")
	require.Equal(t, view.RiverEmbedPrefix, *prefix)

	web, ok := doc.Services["web"]
	require.True(t, ok)
	upstream := web.Environment["AGENT_MANAGER_RIVER_UI_URL"]
	require.NotNil(t, upstream, "the local stack runs a dashboard, so the web role must be "+
		"pointed at it or the River Dashboard entry renders disabled in a stack that has one")
	require.Equal(t, "http://queue-ui:8080", *upstream,
		"the container port, not the published host port: this is reached over the project "+
			"network, and the host mapping is for a browser")
}

// Asserted on the merged configuration, not the YAML anchor, since merges,
// includes and env_files can hand the secret to a service the file does not show.
// Any third holder could mint itself an administrator's session.
func TestExactlyTwoServicesHoldTheSessionMintSecret(t *testing.T) {
	root := repoRootForCompose(t)
	requireDockerCLI(t)

	profiles, err := compose(t, root, "config", "--profiles")
	require.NoError(t, err, profiles)

	args := []string{}
	for _, p := range lines(profiles) {
		args = append(args, "--profile", p)
	}

	var doc struct {
		Services map[string]struct {
			Environment map[string]*string `json:"environment"`
		} `json:"services"`
	}
	raw := composeJSON(t, root, append(args, "config", "--format", "json")...)
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.Services)

	const variable = "AGENT_MANAGER_SESSION_MINT_SECRET"

	var holders []string
	values := map[string]string{}
	for name, service := range doc.Services {
		value, present := service.Environment[variable]
		if !present {
			continue
		}
		holders = append(holders, name)
		require.NotNilf(t, value, "%s passes %s through from the host, so the stack depends on "+
			"a variable that is unset in a normal shell", name, variable)
		require.NotEmptyf(t, *value, "%s holds %s as an empty string, which the api refuses at "+
			"the mint — a sign-in that fails after the password was accepted", name, variable)
		values[name] = *value
	}
	slices.Sort(holders)

	require.Equal(t, []string{"api", "web"}, holders,
		"the api verifies the secret and web presents it. Any other service holding it can ask "+
			"the api to open a session for anyone")
	require.Equal(t, values["api"], values["web"],
		"the two roles read the same variable and disagree about its value, so every sign-in "+
			"fails at the mint with both roles looking correctly configured")
}

// profileCombinations returns every subset of profiles, including the empty one.
func profileCombinations(profiles []string) [][]string {
	slices.Sort(profiles)

	sets := [][]string{{}}
	for _, profile := range profiles {
		for _, set := range slices.Clone(sets) {
			sets = append(sets, append(slices.Clone(set), profile))
		}
	}

	return sets
}

func profileRunName(enabled []string) string {
	if len(enabled) == 0 {
		return "no-profiles"
	}

	return strings.Join(enabled, "+")
}

func declaredServices(t *testing.T, root, file string) []string {
	t.Helper()

	var doc struct {
		Services map[string]yaml.Node `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(readComposeFile(t, root, file), &doc), "%s", file)
	require.NotEmpty(t, doc.Services, "%s declares no services", file)

	names := make([]string, 0, len(doc.Services))
	for name := range doc.Services {
		names = append(names, name)
	}
	slices.Sort(names)

	return names
}

func declaredProjectName(t *testing.T, root, file string) string {
	t.Helper()

	var doc struct {
		Name string `yaml:"name"`
	}
	require.NoError(t, yaml.Unmarshal(readComposeFile(t, root, file), &doc), "%s", file)

	return doc.Name
}

func readComposeFile(t *testing.T, root, file string) []byte {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(root, file))
	require.NoError(t, err)

	return raw
}

// composeDaemonEnv is an allowlist naming only the daemon. COMPOSE_* variables
// such as COMPOSE_FILE would answer the very questions these tests ask, so
// never add one here.
var composeDaemonEnv = []string{
	"DOCKER_HOST",
	"DOCKER_CONTEXT",
	"DOCKER_CONFIG",
	"DOCKER_CERT_PATH",
	"DOCKER_TLS_VERIFY",
	"DOCKER_API_VERSION",

	"HOME",            // ~/.docker, where the context that names the daemon lives
	"XDG_RUNTIME_DIR", // where a rootless daemon's socket lives
	"SSH_AUTH_SOCK",   // a DOCKER_HOST of ssh://…
	"PATH",            // credential helpers, and anything else docker shells out to
}

func composeCmd(t *testing.T, root string, args ...string) *exec.Cmd {
	t.Helper()

	cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
	cmd.Dir = root

	cmd.Env = make([]string, 0, len(composeDaemonEnv))
	for _, key := range composeDaemonEnv {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}

	return cmd
}

func compose(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()

	out, err := composeCmd(t, root, args...).CombinedOutput()

	return string(out), err
}

// composeJSON keeps stderr separate so a deprecation notice cannot corrupt the JSON.
func composeJSON(t *testing.T, root string, args ...string) []byte {
	t.Helper()

	var stdout, stderr bytes.Buffer

	cmd := composeCmd(t, root, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), stderr.String())

	return stdout.Bytes()
}

// requireDockerCLI skips rather than fails, since the build tag alone does not
// guarantee a docker CLI.
func requireDockerCLI(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipping: the docker CLI is absent, and `docker compose config` is the only judge of a merge")
	}
}

func repoRootForCompose(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(root, rootComposeFile))
	require.FileExists(t, filepath.Join(root, infraComposeFile))

	return root
}

func lines(out string) []string {
	var got []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			got = append(got, l)
		}
	}

	return got
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, name := range b {
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}

	return out
}

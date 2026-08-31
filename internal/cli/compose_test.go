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
)

// T015 — the compose split (FR-130, FR-132, SC-110).
//
// The split is a claim about two files that only Compose can settle: that the
// infrastructure half is a whole project on its own, that the argument-free
// command still sees both halves, and that the host ports now handed out from two
// files do not collide. None of it is visible from a Go build, and all of it
// breaks silently — an unresolvable alias, a service quietly redefined, a port
// claimed twice: each shows up at boot as a missing container, not as a parse
// error anyone reads.
//
// Integration-tagged because it needs the docker CLI. It runs `config`, which
// parses and merges and starts nothing.

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
		[]string{"postgres", "minio", "minio-init", "dex", "glauth", "migrate-schema", "migrate-queue"},
		lines(services),
		"FR-129 fixes what infrastructure means; this is the list")
}

func TestBothComposeFilesNameTheSameProject(t *testing.T) {
	root := repoRootForCompose(t)

	// The other half of "a whole project alone": started by itself the infra file
	// has to land in the project the roles come up in afterwards, or they get a
	// different network and cannot resolve `postgres`.
	//
	// Read from the raw keys, because the rendered name is not evidence. Delete
	// `name` and Compose fills it in from the directory — which in a normal clone
	// of this repo is also `agent-manager`, so asserting on `config` output holds
	// everywhere except in the `am/` clone of the one person it protects.
	app := declaredProjectName(t, root, rootComposeFile)
	require.NotEmpty(t, app, "%s declares no name, so it takes whatever the directory is called", rootComposeFile)
	require.Equal(t, app, declaredProjectName(t, root, infraComposeFile),
		"%s started alone would be a different project than `docker compose up`", infraComposeFile)
}

func TestTheArgumentFreeCommandStillSeesBothComposeFiles(t *testing.T) {
	root := repoRootForCompose(t)
	requireDockerCLI(t)

	// No -f and no profile: the single documented command (FR-132).
	out, err := compose(t, root, "config", "--services")
	require.NoError(t, err, out)
	seen := lines(out)

	// One name from each file, so a broken `include:` fails here rather than at
	// `up` — the whole reason R4 chose `include:` over COMPOSE_FILE.
	require.Contains(t, seen, "postgres", "compose.infra.yaml is not being included")
	require.Contains(t, seen, "api", "compose.yaml's own services are missing")

	// And the stronger version: every service either file declares is reachable,
	// profiles included. The profile list is read back from Compose rather than
	// hard-coded, so removing the `workers` profile in a later layer does not
	// have to touch this test.
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

	// Needs no docker: Compose MERGES a service declared in both files, keeping
	// the including file's values and reporting nothing at all. So a service left
	// behind by an incomplete move is invisible to `config` — the only place it
	// can be caught is the raw keys of the two files.
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

	// Compose does not police this. postgres republished as "8082:5432" alongside
	// api renders cleanly and `config` exits 0; it fails at `up`, on whichever
	// service loses the race, and the ports are spread over two files now so
	// whoever edits one cannot see the other's. 003's quickstart really did put
	// the api and the River UI both on 8082.
	profiles, err := compose(t, root, "config", "--profiles")
	require.NoError(t, err, profiles)

	// Every combination, not just everything-enabled. A profile can only add
	// services, so the full set ought to be a superset of the rest — but that is
	// Compose's rule rather than this repo's, and a subset costs one `config`.
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
					// An unpublished port is not a claim on port 0: postgres asks
					// for an ephemeral host port, and two of those cannot collide.
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

// Every subset of the profiles Compose reported, the empty one — the documented
// argument-free command — included.
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

// The variables Compose is allowed to see, built up from nothing rather than
// filtered down from the caller's environment.
//
// COMPOSE_FILE, COMPOSE_PROFILES, COMPOSE_PROJECT_NAME and COMPOSE_ENV_FILES
// answer, from the environment, the very questions this file asks Compose: with
// COMPOSE_FILE exported, every assertion here passes against a compose.yaml whose
// `include:` has been deleted, and COMPOSE_PROJECT_NAME can supply a project name
// no file declares. That invisibility is what R4 rejected. An allowlist is also
// what keeps this honest for the COMPOSE_* variables added after it was written,
// and for anything a future `${...}` in either file would interpolate.
//
// What is kept names the DAEMON, never the files or the project: strip these and
// there is no socket to reach, so every test here errors instead of asserting.
// Adding a COMPOSE_* variable back to this list re-opens the hole.
var composeDaemonEnv = []string{
	// Which daemon, and how to reach and authenticate to it.
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

// Kept apart from compose(): the combined output is what makes a failure readable
// everywhere else, but one deprecation notice on stderr would be spliced into the
// middle of the JSON.
func composeJSON(t *testing.T, root string, args ...string) []byte {
	t.Helper()

	var stdout, stderr bytes.Buffer

	cmd := composeCmd(t, root, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), stderr.String())

	return stdout.Bytes()
}

// The unit-test CI job has no docker, and this file's build tag is not what
// separates the two jobs — the integration job is the one with a daemon. Skipping
// on a missing binary keeps `go test -tags=integration ./internal/cli/` runnable
// anywhere, which matters because these assertions are about text files.
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

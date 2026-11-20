package checks

import (
	"regexp"
	"strings"
)

// launcherValueFlags are the flags whose next word is a value, not the
// package, per launcher. A flag naming the package itself is in
// launcherPackageFlags.
var (
	launcherValueFlags = map[string][]string{
		"npx":  {"-c", "--call", "--cache", "--registry", "--userconfig"},
		"uvx":  {"--with", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--with-requirements"},
		"pipx": {"--python", "--pip-args", "--index-url"},
		"docker": {"-e", "--env", "--env-file", "-v", "--volume", "--name", "-p", "--publish", "--network", "--net",
			"--entrypoint", "-w", "--workdir", "--mount", "-u", "--user", "--platform", "-l", "--label", "--pull",
			"--add-host", "--cpus", "-m", "--memory", "--hostname", "-h", "--device", "--cap-add", "--cap-drop",
			"--security-opt", "--tmpfs", "--ulimit", "--runtime", "--restart", "--log-driver", "--dns"},
	}
	launcherPackageFlags = map[string][]string{
		"npx":  {"-p", "--package"},
		"uvx":  {"--from"},
		"pipx": {"--spec"},
	}
)

// launchedPackage is the package spec a launcher command fetches and runs,
// or "" when the command is not a launch: `pnpm install` or `docker ps`.
func launchedPackage(name string, args []string) string {
	family := name
	switch name {
	case "npx", "bunx":
		family = "npx"
	case "pnpm":
		if len(args) == 0 || args[0] != "dlx" {
			return ""
		}
		family, args = "npx", args[1:]
	case "pipx":
		if len(args) == 0 || args[0] != "run" {
			return ""
		}
		args = args[1:]
	case "docker", "podman":
		if len(args) > 1 && args[0] == "container" {
			args = args[1:]
		}
		if len(args) == 0 || args[0] != "run" {
			return ""
		}
		family, args = "docker", args[1:]
	case "uvx":
	default:
		return ""
	}

	valueFlags, packageFlags := launcherValueFlags[family], launcherPackageFlags[family]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if !strings.HasPrefix(arg, "-") {
			return arg
		}
		flag, value, inline := strings.Cut(arg, "=")
		if contains(packageFlags, flag) {
			if inline {
				return value
			}
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if !inline && contains(valueFlags, flag) {
			i++
		}
	}
	return ""
}

// launcherUnpinned judges a `launcher spec` value: npm-style launchers need
// name@x.y.z, Python ones name==x.y.z, and an image a non-latest tag or a
// digest. A spec built from an expansion cannot be judged and is unpinned.
func launcherUnpinned(value string) bool {
	launcher, spec, _ := strings.Cut(value, " ")
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.ContainsAny(spec, "$`") {
		return true
	}
	switch launcher {
	case "uvx", "pipx":
		_, version, found := strings.Cut(spec, "==")
		return !found || !exactPEP440.MatchString(version)
	case "docker", "podman":
		if strings.Contains(spec, "@sha256:") {
			return false
		}
		name := spec[strings.LastIndex(spec, "/")+1:]
		_, tag, found := strings.Cut(name, ":")
		return !found || tag == "" || strings.EqualFold(tag, "latest")
	default:
		at := strings.LastIndex(spec, "@")
		if at <= 0 {
			return true
		}
		return !exactSemver.MatchString(spec[at+1:])
	}
}

var exactPEP440 = regexp.MustCompile(`^\d+(\.\d+)*([abc]|rc|\.post|\.dev)?\d*$`)

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

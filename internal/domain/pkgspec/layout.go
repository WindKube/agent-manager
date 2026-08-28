package pkgspec

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"agent-manager/internal/bundle"
)

// The spec-layout filter (T040, FR-005).
//
// FR-005 has two halves and the second is the one that gets forgotten: the system
// MUST discard files outside the spec layout AND MUST report which paths were
// discarded, before the user commits to registration. Dropping silently would
// pass every test that only looks at the stored tree and would fail US1 scenario
// 2, whose whole point is that the preview says `.github/, README.md → outside
// spec, dropped`.

// ErrNoManifest means neither manifest sits at the package root, so there is
// nothing to register. It is an ingestion failure, never a scan finding.
var ErrNoManifest = errors.New("no plugin.json or SKILL.md at the package root")

// The directories an Agent Skills tree may carry beside SKILL.md. The
// specification describes a skill as a directory holding SKILL.md plus the
// resources it references, so the set is closed here rather than "everything":
// a closed set is what makes the drop report meaningful.
var skillSupportDirs = []string{"scripts", "references", "assets"}

// reverseDomainLabel is one label of a reverse-domain namespace directory such as
// `com.anthropic.claude-code`. Two or more labels are required, because a single
// label is just a directory and a dotted name with one label is a file with an
// extension.
var reverseDomainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// LayoutEntry is one line of the design's archive-contents panel.
type LayoutEntry struct {
	// Path is what the panel shows: a file, a directory with its trailing slash,
	// or several dropped paths joined by ", " — matching the design's
	// `.github/, README.md` line.
	Path string

	// Note is the right-hand column: `schema valid`, `4 skills`, `1 server`,
	// `client extension`, `outside spec, dropped`.
	Note string

	// Kept is the mark: true renders `✓`, false renders `–`.
	Kept bool
}

// LayoutReport is what the filter did, in the order the panel lists it.
type LayoutReport struct {
	Entries []LayoutEntry

	// Dropped is every discarded path in full, not the grouped rendering. The
	// panel shows the groups; the audit trail and the tests need the paths.
	Dropped []string

	// Kept is every retained path, rerooted.
	Kept []string
}

// DroppedGroups renders the discarded paths the way the panel joins them: one
// entry per top-level name, so `.github/workflows/ci.yml` and `.github/CODEOWNERS`
// collapse to `.github/`.
func (r LayoutReport) DroppedGroups() []string {
	seen := make(map[string]struct{}, len(r.Dropped))
	groups := make([]string, 0, len(r.Dropped))
	for _, path := range r.Dropped {
		group := path
		if segments := splitPath(path); len(segments) > 1 {
			group = segments[0] + "/"
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
	}
	sort.Strings(groups)
	return groups
}

// layout is the structural result of filtering, before any manifest is read.
type layout struct {
	kind    Kind
	files   *bundle.Bundle
	kept    []string
	dropped []string

	// skillDirs are the `skills/<name>` directories present, sorted.
	skillDirs []string

	// extDirs are the reverse-domain namespace directories present, sorted, each
	// with the first path under it so the panel can show
	// `com.anthropic.claude-code/hooks/`.
	extDirs []extDir

	hasMCP bool
}

type extDir struct {
	name string
	// firstChild is the first segment inside the directory, for the panel's label.
	firstChild string
}

// filterLayout reroots tree at root, decides the package kind from which manifest
// is present, and partitions the paths.
//
// Rejecting rather than repairing is the rule here as everywhere on this path: a
// root that names nothing is an error, not an empty tree, because "we found no
// files under the subdirectory you asked for" and "the subdirectory you asked for
// does not exist" are the same fetch error and neither is a successful publish of
// nothing.
func filterLayout(tree *bundle.Bundle, root string) (*layout, error) {
	if tree == nil {
		return nil, errors.New("layout filter: no tree")
	}

	rerooted, err := reroot(tree, root)
	if err != nil {
		return nil, err
	}

	dirs := directorySegments(rerooted)

	var kind Kind
	switch {
	case contains(rerooted, PluginManifest):
		kind = KindPlugin
	case contains(rerooted, SkillManifest):
		kind = KindSkill
	default:
		return nil, fmt.Errorf("%w (root %q)", ErrNoManifest, displayRoot(root))
	}

	out := &layout{kind: kind, files: bundle.New()}
	extSeen := make(map[string]string)

	for _, path := range sortedPaths(rerooted) {
		if keptPath(kind, path, dirs) {
			out.kept = append(out.kept, path)
			if err := out.files.Add(path, rerooted[path].Mode, rerooted[path].Data); err != nil {
				return nil, fmt.Errorf("layout filter: %w", err)
			}
			continue
		}
		out.dropped = append(out.dropped, path)
	}

	for _, path := range out.kept {
		segments := splitPath(path)
		switch {
		case path == MCPConfigFile:
			out.hasMCP = true
		case segments[0] == SkillsDir && len(segments) > 1:
			dir := SkillsDir + "/" + segments[1]
			if !containsString(out.skillDirs, dir) {
				out.skillDirs = append(out.skillDirs, dir)
			}
		case isReverseDomain(segments[0]) && len(segments) > 1:
			if _, ok := extSeen[segments[0]]; !ok {
				extSeen[segments[0]] = segments[1]
			}
		}
	}

	for name, firstChild := range extSeen {
		out.extDirs = append(out.extDirs, extDir{name: name, firstChild: firstChild})
	}
	sort.Slice(out.extDirs, func(i, j int) bool { return out.extDirs[i].name < out.extDirs[j].name })
	sort.Strings(out.skillDirs)

	return out, nil
}

// keptPath is the whole layout rule, per kind.
func keptPath(kind Kind, path string, dirs map[string]struct{}) bool {
	segments := splitPath(path)
	if len(segments) == 0 {
		return false
	}
	top := segments[0]

	if kind == KindSkill {
		if path == SkillManifest {
			return true
		}
		return len(segments) > 1 && containsString(skillSupportDirs, top)
	}

	switch {
	case path == PluginManifest, path == MCPConfigFile:
		return true
	case top == SkillsDir && len(segments) > 1:
		return true
	case len(segments) > 1 && isReverseDomain(top):
		// A reverse-domain namespace is a client extension directory. Only a
		// directory qualifies: `plugin.json` and `mcp.json` also carry a dot, and
		// the `dirs` set is what keeps a dotted FILE from being read as a namespace.
		_, isDir := dirs[top]
		return isDir
	default:
		return false
	}
}

// isReverseDomain reports whether a directory name is a reverse-domain namespace.
func isReverseDomain(name string) bool {
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	// The leading label is a TLD-shaped token (`com`, `dev`, `io`); a single
	// character there is a filename like `a.b`, not a namespace.
	if len(labels[0]) < 2 {
		return false
	}
	for _, label := range labels {
		if !reverseDomainLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// reroot returns the files under root, keyed by their path relative to it.
func reroot(tree *bundle.Bundle, root string) (map[string]bundle.File, error) {
	clean := strings.Trim(strings.TrimSpace(root), "/")
	if clean == "." {
		clean = ""
	}
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("layout filter: root %q contains a parent-directory reference", root)
	}

	out := make(map[string]bundle.File, tree.Len())
	prefix := ""
	if clean != "" {
		prefix = clean + "/"
	}
	for _, file := range tree.Files() {
		if prefix == "" {
			out[file.Path] = file
			continue
		}
		if rest, ok := strings.CutPrefix(file.Path, prefix); ok && rest != "" {
			out[rest] = bundle.File{Path: rest, Mode: file.Mode, Data: file.Data}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: nothing under %q", ErrNoManifest, displayRoot(root))
	}
	return out, nil
}

func displayRoot(root string) string {
	clean := strings.Trim(strings.TrimSpace(root), "/")
	if clean == "" || clean == "." {
		return "."
	}
	return clean
}

// directorySegments is the set of top-level names that are directories, i.e. that
// appear as the first of two or more segments.
func directorySegments(files map[string]bundle.File) map[string]struct{} {
	dirs := make(map[string]struct{})
	for path := range files {
		if segments := splitPath(path); len(segments) > 1 {
			dirs[segments[0]] = struct{}{}
		}
	}
	return dirs
}

func sortedPaths(files map[string]bundle.File) []string {
	out := make([]string, 0, len(files))
	for path := range files {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func contains(files map[string]bundle.File, path string) bool {
	_, ok := files[path]
	return ok
}

func plural(n int, singular string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %ss", n, singular)
}

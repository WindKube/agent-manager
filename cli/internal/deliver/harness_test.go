package deliver_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"

	"github.com/WindKube/agent-manager/cli/internal/apply"
	"github.com/WindKube/agent-manager/cli/internal/deliver"
	"github.com/WindKube/agent-manager/cli/internal/hub"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/plan"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

const hubURL = "https://hub.example.com"

// harness is one machine: a home, a record and every target this build
// writes, synced through the real plan and applier with a real Deliverer.
type harness struct {
	t       *testing.T
	home    string
	reg     *layout.Registry
	rec     *record.Record
	recPath string
	bundles map[string][]byte // by lockfile digest
	log     *captureLog
	claude  *fakeClaude // nil: no claude on PATH
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	home := t.TempDir()
	reg, err := layout.NewRegistry(layout.Config{HomeDir: home, PluginRoot: filepath.Join(home, ".agent-manager", "hub", "plugins")})
	require.NoError(t, err)
	return &harness{
		t: t, home: home, reg: reg, rec: record.New(hubURL),
		recPath: filepath.Join(home, ".agent-manager", "hub", record.FileName),
		bundles: map[string][]byte{},
		log:     &captureLog{},
		claude:  &fakeClaude{config: filepath.Join(home, ".claude.json")},
	}
}

// pluginEntry packs files as a plugin bundle and returns its lockfile entry.
func (h *harness) pluginEntry(id, version string, files map[string]string) hub.LockfileEntry {
	b := packBundle(h.t, files)
	sum := sha256.Sum256(b)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	h.bundles[digest] = b
	return hub.LockfileEntry{
		Id: id, Kind: hub.Plugin, Version: version, Digest: digest,
		ObjectKey: "bundles/" + id + "/" + version + "/bundle.tar.zst", Resolution: "pinned", Verdict: "clean",
	}
}

func lockfile(slug string, targets []record.Target, entries ...hub.LockfileEntry) *hub.Lockfile {
	tg := make([]hub.LockfileTargets, 0, len(targets))
	for _, name := range targets {
		tg = append(tg, hub.LockfileTargets(name))
	}
	if entries == nil {
		entries = []hub.LockfileEntry{}
	}
	return &hub.Lockfile{
		SchemaVersion: "1.0.0", Profile: hub.LockfileProfile{Slug: slug, Name: slug}, Revision: 3,
		Gate: "block", Entries: entries, Skipped: []hub.LockfileSkip{}, Targets: tg,
	}
}

func (h *harness) sync(lf *hub.Lockfile, force bool) *apply.Result {
	h.t.Helper()
	targets := map[record.Target]layout.Target{}
	var planTargets []plan.Target
	for _, name := range layout.KnownTargetNames() {
		t, err := h.reg.Resolve(record.Target(name))
		require.NoError(h.t, err)
		targets[t.Name()] = t
	}
	for name, t := range targets {
		pt := plan.Target{Name: name, Dest: func(id string, kind record.Kind) (string, error) {
			p, err := t.Place(layout.Request{ID: id, Kind: kind})
			return p.Dest, err
		}}
		for other, ot := range targets {
			if other != name && slices.Contains(t.AlsoReadsSkillsFrom(), ot.Root()) {
				pt.ServedBy = append(pt.ServedBy, other)
			}
		}
		planTargets = append(planTargets, pt)
	}
	sort.Slice(planTargets, func(i, j int) bool { return planTargets[i].Name < planTargets[j].Name })

	p, err := plan.Compute(plan.Inputs{Lockfiles: []*hub.Lockfile{lf}, Record: h.rec, Targets: planTargets})
	require.NoError(h.t, err)
	require.False(h.t, p.Refuses(), "%v", p.ConflictError())

	home, err := apply.OpenHome(h.home)
	require.NoError(h.t, err)
	var profileTargets []record.Target
	for _, tg := range lf.Targets {
		profileTargets = append(profileTargets, record.Target(tg))
	}
	slices.Sort(profileTargets)
	var claude deliver.ClaudeCLI
	if h.claude != nil {
		claude = h.claude.run
	}
	applier, err := apply.New(apply.Config{
		Home: home, Record: h.rec, RecordPath: h.recPath,
		Profiles: []apply.ProfileState{{Slug: lf.Profile.Slug, Revision: int(lf.Revision), Targets: profileTargets}},
		Bundles:  bundleSource(h.bundles), Force: force, Log: h.log,
		Fingerprints: apply.TreeFingerprinter{}, Verifier: apply.TreeFingerprinter{},
		Components: &deliver.Deliverer{
			Targets: targets, Home: home, Force: force, Log: h.log, Claude: claude,
			ProfileTargets: map[string][]record.Target{lf.Profile.Slug: profileTargets},
		},
	})
	require.NoError(h.t, err)
	res, _ := applier.Apply(context.Background(), p)
	return res
}

func (h *harness) entry(target record.Target, id string) record.Entry {
	h.t.Helper()
	refs := h.rec.Refs()
	for i := range refs {
		if refs[i].Entry.Target == target && refs[i].Entry.ID == id {
			return refs[i].Entry
		}
	}
	h.t.Fatalf("no record entry for %s %s", target, id)
	return record.Entry{}
}

func (h *harness) path(rel string) string { return filepath.Join(h.home, filepath.FromSlash(rel)) }

func (h *harness) write(rel, body string) {
	h.t.Helper()
	p := h.path(rel)
	require.NoError(h.t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(h.t, os.WriteFile(p, []byte(body), 0o644))
}

func (h *harness) read(rel string) string {
	h.t.Helper()
	b, err := os.ReadFile(h.path(rel))
	require.NoError(h.t, err)
	return string(b)
}

// snapshot is every file under the home except amctl's own state, by content.
func (h *harness) snapshot() map[string]string {
	h.t.Helper()
	out := map[string]string{}
	require.NoError(h.t, filepath.WalkDir(h.home, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(h.home, p)
		if d.IsDir() || strings.HasPrefix(rel, ".agent-manager") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(b)
		return nil
	}))
	return out
}

func requireNoFailures(t *testing.T, res *apply.Result) {
	t.Helper()
	require.Empty(t, res.Failed, "%v", res.Err())
}

// fakeClaude does what `claude mcp add-json/remove --scope user` does to the
// user config file, including refusing to add twice or remove what is absent.
type fakeClaude struct {
	config string
	calls  []string
}

func (f *fakeClaude) run(_ context.Context, args ...string) error {
	f.calls = append(f.calls, strings.Join(args[:2], " ")+" "+args[2])
	cfg := map[string]any{}
	if b, err := os.ReadFile(f.config); err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return err
		}
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	name := args[2]
	switch strings.Join(args[:2], " ") {
	case "mcp add-json":
		if _, ok := servers[name]; ok {
			return fmt.Errorf("MCP server %s already exists in user config", name)
		}
		var v any
		if err := json.Unmarshal([]byte(args[3]), &v); err != nil {
			return err
		}
		servers[name] = v
	case "mcp remove":
		if _, ok := servers[name]; !ok {
			return fmt.Errorf("no user-scoped MCP server found with name: %s", name)
		}
		delete(servers, name)
	default:
		return fmt.Errorf("fake claude: unexpected %v", args)
	}
	cfg["mcpServers"] = servers
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(f.config, b, 0o600)
}

type bundleSource map[string][]byte

func (b bundleSource) Bundle(_ context.Context, c plan.Change) ([]byte, error) {
	return b[c.Digest.Lockfile()], nil
}

type captureLog struct{ lines []string }

func (l *captureLog) Warnf(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *captureLog) Debugf(string, ...any) {}

func packBundle(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	modTime := time.Date(2026, 4, 17, 9, 12, 4, 0, time.UTC)
	dirs := map[string]bool{}
	names := slices.Sorted(maps.Keys(files))
	for _, name := range names {
		for i, c := range name {
			if c == '/' && !dirs[name[:i+1]] {
				dirs[name[:i+1]] = true
				require.NoError(t, tw.WriteHeader(&tar.Header{
					Name: name[:i+1], Typeflag: tar.TypeDir, Mode: 0o755, ModTime: modTime, Format: tar.FormatPAX,
				}))
			}
		}
	}
	for _, name := range names {
		body := files[name]
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)), ModTime: modTime, Format: tar.FormatPAX,
		}))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	var out bytes.Buffer
	zw, err := zstd.NewWriter(&out)
	require.NoError(t, err)
	_, err = zw.Write(tarBuf.Bytes())
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return out.Bytes()
}

// kitFiles is a small plugin: two skills, by default.
func kitFiles(extra map[string]string) map[string]string {
	files := map[string]string{
		"plugin.json":           `{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"kit","version":"1.0.0","description":"kit"}`,
		"skills/alpha/SKILL.md": "---\nname: alpha\ndescription: Alpha.\n---\nAlpha body\n",
		"skills/alpha/run.sh":   "#!/bin/sh\necho alpha\n",
		"skills/beta/SKILL.md":  "---\nname: beta\ndescription: Beta.\n---\nBeta body\n",
	}
	for k, v := range extra {
		if v == "" {
			delete(files, k)
			continue
		}
		files[k] = v
	}
	return files
}

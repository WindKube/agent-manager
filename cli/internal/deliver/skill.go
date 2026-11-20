package deliver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/WindKube/agent-manager/cli/internal/apply"
	"github.com/WindKube/agent-manager/cli/internal/layout"
	"github.com/WindKube/agent-manager/cli/internal/record"
)

// skillSlots places each skill as `<ns>--<package>--<skill>` under the
// target's skills root: injective, since `--` cannot occur inside a segment.
func (p *placer) skillSlots() []slot {
	var out []slot
	servedBy := p.servedBy()
	for _, s := range p.plugin.Skills {
		switch {
		case s.UsesPluginRoot:
			p.skip(record.ComponentSkill, s.Name, SkipPluginRoot)
			continue
		case servedBy != "":
			p.skip(record.ComponentSkill, s.Name, SkipServedBy+" "+servedBy)
			continue
		}
		dirName := p.pkg.DirName() + layout.DirSeparator + s.Name
		if err := p.validSkillDir(s.Name, dirName); err != nil {
			p.skip(record.ComponentSkill, s.Name, SkipUnusableName+": "+err.Error())
			continue
		}
		src := filepath.Join(p.stagedDir, filepath.FromSlash(s.Dir))
		digest, err := treeDigest(src)
		if err != nil {
			p.skip(record.ComponentSkill, s.Name, "unreadable: "+err.Error())
			continue
		}
		out = append(out, &dirSlot{
			d: p.d,
			comp: record.Component{
				Kind: record.ComponentSkill, Name: s.Name,
				Path: filepath.Join(p.target.Components().Skills, dirName), SHA256: digest,
			},
			src: filepath.Join(p.change.Dest, filepath.FromSlash(s.Dir)),
		})
	}
	return out
}

func (p *placer) validSkillDir(name, dirName string) error {
	if name == "" || strings.Contains(name, layout.DirSeparator) || strings.HasPrefix(name, ".") {
		return fmt.Errorf("skill %q", name)
	}
	if err := layout.ValidateDirName(dirName); err != nil {
		return err
	}
	if p.change.Target == record.TargetClaudeCode {
		return layout.ValidateClaudeCodeSkillDirName(dirName)
	}
	return nil
}

// servedBy names the skills root, written by another target in this profile,
// that this target's agent already loads; "" when it loads none.
func (p *placer) servedBy() string {
	also := p.target.AlsoReadsSkillsFrom()
	if len(also) == 0 {
		return ""
	}
	for _, other := range p.d.ProfileTargets[p.change.Profile] {
		if other == p.change.Target {
			continue
		}
		t, ok := p.d.Targets[other]
		if ok && slices.Contains(also, t.Root()) {
			return t.Root() + " (" + string(other) + ")"
		}
	}
	return ""
}

// dirSlot is a skill directory, installed by a staged copy and a swap.
type dirSlot struct {
	d    *Deliverer
	comp record.Component
	src  string // the skill inside the plugin's installed directory
}

func (s *dirSlot) ref() record.Component { return s.comp }

func (s *dirSlot) current(string) (string, error) {
	if _, err := s.d.contained(s.comp.Path); err != nil {
		return "", err
	}
	digest, err := treeDigest(s.comp.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return digest, err
}

func (s *dirSlot) write(context.Context, string) (string, error) {
	dest, err := s.d.contained(s.comp.Path)
	if err != nil {
		return "", err
	}
	stagingRoot := layout.StagingRoot(dest)
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		return "", err
	}
	staged := filepath.Join(stagingRoot, filepath.Base(dest))
	if err := os.RemoveAll(staged); err != nil {
		return "", err
	}
	if err := os.CopyFS(staged, os.DirFS(s.src)); err != nil {
		_ = os.RemoveAll(staged)
		return "", fmt.Errorf("copy %s: %w", s.src, err)
	}
	if _, err := apply.Swap(staged, dest); err != nil {
		_ = os.RemoveAll(staged)
		return "", err
	}
	_ = apply.PruneStagingRoot(dest)
	return treeDigest(dest)
}

func (s *dirSlot) remove(context.Context, string) error {
	dest, err := s.d.contained(s.comp.Path)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(dest))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	name := filepath.Base(dest)
	if err := root.RemoveAll(name); err != nil {
		return err
	}
	return root.RemoveAll(name + apply.AsideSuffix)
}

func (d *Deliverer) contained(p string) (string, error) {
	if d.Home == nil {
		return "", errors.New("internal: no home to contain writes in")
	}
	c, err := d.Home.Contains(p)
	if err != nil {
		return "", err
	}
	return c.Dest, nil
}

// treeDigest fingerprints a directory's content: every path, its kind and,
// for a file, its bytes. Modes are left out; content is what an edit changes.
func treeDigest(dir string) (string, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return sum([]byte("not a directory: " + info.Mode().String())), nil
	}
	var lines []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		switch {
		case rel == ".":
		case d.IsDir():
			lines = append(lines, "d "+rel)
		case d.Type().IsRegular():
			h, herr := fileSum(p)
			if herr != nil {
				return herr
			}
			lines = append(lines, "f "+rel+" "+h)
		default:
			lines = append(lines, "o "+rel+" "+d.Type().String())
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	slices.Sort(lines)
	return sum([]byte(strings.Join(lines, "\n"))), nil
}

func fileSum(p string) (string, error) {
	f, err := os.Open(p) //nolint:gosec // a path inside a contained, amctl-placed component
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

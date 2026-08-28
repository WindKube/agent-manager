package bundle

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
)

// ErrDuplicatePath is returned by Bundle.Add when a path is already present. A bundle is
// the identity of a stored version (FR-007), so a second write to the same path is a
// caller bug, never a silent overwrite.
var ErrDuplicatePath = errors.New("path already present in bundle")

// FileMode and ExecMode are the only two modes a bundle records. Archive modes are
// attacker-controlled, so setuid, setgid and sticky bits are dropped at extraction and
// the executable bit is the sole surviving distinction; that also keeps Pack's output a
// function of the tree alone.
const (
	FileMode fs.FileMode = 0o644
	ExecMode fs.FileMode = 0o755
)

// File is one regular file of an extracted tree. Data is owned by the Bundle; callers
// must not mutate it.
type File struct {
	Path string
	Mode fs.FileMode
	Data []byte
}

// Bundle is an in-memory package tree: regular files only, keyed by slash-separated
// relative path. Directories are implicit, so an archive's directory members carry no
// information past the path checks they must pass.
type Bundle struct {
	byPath map[string]int
	files  []File
	sorted bool
	total  int64
}

func New() *Bundle {
	return &Bundle{byPath: make(map[string]int)}
}

// Add records one regular file. path must already be validated; Add enforces only
// uniqueness.
func (b *Bundle) Add(path string, mode fs.FileMode, data []byte) error {
	if b.byPath == nil {
		b.byPath = make(map[string]int)
	}
	if _, ok := b.byPath[path]; ok {
		return fmt.Errorf("%q: %w", path, ErrDuplicatePath)
	}
	normalised := FileMode
	if mode.Perm()&0o111 != 0 {
		normalised = ExecMode
	}
	b.byPath[path] = len(b.files)
	b.files = append(b.files, File{Path: path, Mode: normalised, Data: data})
	b.total += int64(len(data))
	b.sorted = false
	return nil
}

func (b *Bundle) Lookup(path string) (File, bool) {
	i, ok := b.byPath[path]
	if !ok {
		return File{}, false
	}
	return b.files[i], true
}

func (b *Bundle) Has(path string) bool {
	_, ok := b.byPath[path]
	return ok
}

// Files returns every file in path order. The order is stable and is what Pack digests,
// so iteration never depends on archive order or map iteration.
func (b *Bundle) Files() []File {
	b.ensureSorted()
	return b.files
}

func (b *Bundle) Paths() []string {
	b.ensureSorted()
	out := make([]string, len(b.files))
	for i, f := range b.files {
		out[i] = f.Path
	}
	return out
}

func (b *Bundle) Len() int { return len(b.files) }

// TotalBytes is the uncompressed size of the tree.
func (b *Bundle) TotalBytes() int64 { return b.total }

func (b *Bundle) ensureSorted() {
	if b.sorted {
		return
	}
	sort.Slice(b.files, func(i, j int) bool { return b.files[i].Path < b.files[j].Path })
	for i, f := range b.files {
		b.byPath[f.Path] = i
	}
	b.sorted = true
}

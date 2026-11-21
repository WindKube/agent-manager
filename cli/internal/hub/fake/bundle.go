package fake

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

// blob is one served object with its digest in both contract encodings, derived from Bytes.
type blob struct {
	Bytes  []byte
	Hex    string // 64 lowercase hex, no scheme
	Base64 string // standard base64 of the same 32 bytes
}

func newBlob(b []byte) blob {
	sum := sha256.Sum256(b)
	return blob{
		Bytes:  b,
		Hex:    hex.EncodeToString(sum[:]),
		Base64: base64.StdEncoding.EncodeToString(sum[:]),
	}
}

// LockfileDigest is the `sha256:<64 hex>` form a lockfile entry carries.
func (b blob) LockfileDigest() string { return "sha256:" + b.Hex }

// HeaderDigest is the RFC 3230 form, standard base64 (internal/cache refuses base64url).
func (b blob) HeaderDigest() string { return "sha-256=" + b.Base64 }

// ETag is the quoted digest, as the hub's is.
func (b blob) ETag() string { return `"` + b.Hex + `"` }

type bundleFile struct {
	Name string
	Body string
	Mode int64
}

// packBundle writes a tar+zstd bundle whose root is the skill directory. No top-level name may be a
// plugin-adopting subdir, or internal/archive would refuse it.
func packBundle(files []bundleFile) blob {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	// fixed timestamp: a digest that changes per run can't be a golden expectation
	modTime := time.Date(2026, 4, 17, 9, 12, 4, 0, time.UTC)

	writeHeader := func(h *tar.Header) {
		h.ModTime = modTime
		h.Format = tar.FormatPAX
		if err := tw.WriteHeader(h); err != nil {
			panic(fmt.Sprintf("fake: tar header %q: %v", h.Name, err))
		}
	}

	dirs := map[string]bool{}
	for _, f := range files {
		for i, c := range f.Name {
			if c != '/' {
				continue
			}
			dir := f.Name[:i+1]
			if dirs[dir] {
				continue
			}
			dirs[dir] = true
			writeHeader(&tar.Header{Name: dir, Typeflag: tar.TypeDir, Mode: 0o755})
		}
	}
	for _, f := range files {
		mode := f.Mode
		if mode == 0 {
			mode = 0o644
		}
		writeHeader(&tar.Header{
			Name:     f.Name,
			Typeflag: tar.TypeReg,
			Mode:     mode,
			Size:     int64(len(f.Body)),
		})
		if _, err := tw.Write([]byte(f.Body)); err != nil {
			panic(fmt.Sprintf("fake: tar body %q: %v", f.Name, err))
		}
	}
	if err := tw.Close(); err != nil {
		panic(fmt.Sprintf("fake: tar close: %v", err))
	}

	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		panic(fmt.Sprintf("fake: zstd writer: %v", err))
	}
	out := enc.EncodeAll(tarBuf.Bytes(), nil)
	if err := enc.Close(); err != nil {
		panic(fmt.Sprintf("fake: zstd close: %v", err))
	}
	return newBlob(out)
}

func skillFiles(id, version string) []bundleFile {
	return []bundleFile{
		{Name: "SKILL.md", Body: "---\nname: " + id + "\nversion: " + version + "\n---\n\n# " + id + "\n"},
		{Name: "references/usage.md", Body: "Usage notes for " + id + " " + version + ".\n"},
		{Name: "scripts/check.sh", Body: "#!/bin/sh\necho " + id + "\n", Mode: 0o755},
	}
}

// pluginFiles is an Agent Plugins tree: plugin.json, one skill and one MCP server.
func pluginFiles(id, version string) []bundleFile {
	_, name, _ := strings.Cut(id, "/")
	return []bundleFile{
		{Name: "plugin.json", Body: `{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",` +
			`"name":"` + name + `","version":"` + version + `","description":"fixture plugin"}`},
		{Name: "mcp.json", Body: `{"mcpServers":{"lint":{"command":"lint-mcp","args":["--stdio"]}}}`},
		{Name: "skills/review/SKILL.md", Body: "---\nname: review\ndescription: Reviews.\n---\nReview " + id + "\n"},
	}
}

package fake

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/klauspost/compress/zstd"
)

// blob is one served object: the exact bytes, and the digest of those bytes in
// both encodings the contract uses. Nothing here is hand-written — Hex and Header
// are derived from Bytes at construction, so the two can only agree.
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

// HeaderDigest is the RFC 3230 form the Digest response header carries. Note the
// hyphen in `sha-256` and that the value is STANDARD base64, not base64url — the
// contract's pattern is ^sha-256=[A-Za-z0-9+/=]+$ and internal/cache refuses
// base64url outright.
func (b blob) HeaderDigest() string { return "sha-256=" + b.Base64 }

// ETag is quoted, as RFC 9110 requires. The hub uses the digest for it; so does
// this, because a test that asserts they differ would be asserting an accident.
func (b blob) ETag() string { return `"` + b.Hex + `"` }

// bundleFile is one member of a built bundle.
type bundleFile struct {
	Name string
	Body string
	Mode int64
}

// packBundle writes a tar+zstd bundle shaped like a real claude-code SKILL
// directory: the destination root IS the skill directory, so SKILL.md sits at the
// archive root and there is no wrapping directory.
//
// The member set is chosen to be one internal/archive ACCEPTS. In particular no
// top-level directory here is one of layout.IsClaudeCodePluginAdoptingSubdir's
// names (`hooks`, `commands`, `agents`, …): a bundle carrying one would be refused
// by the extractor, so a fake that served one would make every install test fail
// for a reason unrelated to what it was testing.
func packBundle(files []bundleFile) blob {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	// A fixed timestamp keeps the bundle bytes — and therefore the digest — stable
	// across runs. A digest that changes per run cannot be written into a golden
	// expectation, and a test that reads the digest out of the fake instead is a
	// test that has stopped checking the digest.
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

// skillFiles is the default member set: enough structure to prove a nested
// directory round-trips, small enough that no cap is anywhere near.
func skillFiles(id, version string) []bundleFile {
	return []bundleFile{
		{Name: "SKILL.md", Body: "---\nname: " + id + "\nversion: " + version + "\n---\n\n# " + id + "\n"},
		{Name: "references/usage.md", Body: "Usage notes for " + id + " " + version + ".\n"},
		{Name: "scripts/check.sh", Body: "#!/bin/sh\necho " + id + "\n", Mode: 0o755},
	}
}

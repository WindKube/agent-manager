package bundle

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

func sampleBundle(t *testing.T) *Bundle {
	t.Helper()
	b := New()
	// Deliberately out of path order: Pack must not inherit insertion order.
	require.NoError(t, b.Add("skills/demo/SKILL.md", 0o644, []byte("# demo")))
	require.NoError(t, b.Add("plugin.json", 0o644, []byte(`{"name":"demo"}`)))
	require.NoError(t, b.Add("scripts/run.sh", 0o755, []byte("#!/bin/sh\necho hi\n")))
	return b
}

func packBytes(t *testing.T, b *Bundle) (packed []byte, digest [32]byte, size int64) {
	t.Helper()
	r, digest, size, err := Pack(b)
	require.NoError(t, err)
	data, readErr := io.ReadAll(r)
	require.NoError(t, readErr)
	require.Equal(t, size, int64(len(data)))
	return data, digest, size
}

func TestPackIsDeterministic(t *testing.T) {
	first, firstDigest, firstSize := packBytes(t, sampleBundle(t))
	second, secondDigest, secondSize := packBytes(t, sampleBundle(t))

	require.Equal(t, first, second)
	require.Equal(t, firstDigest, secondDigest)
	require.Equal(t, firstSize, secondSize)
	require.Len(t, hex.EncodeToString(firstDigest[:]), 64)
}

func TestPackIgnoresInsertionOrder(t *testing.T) {
	// FR-007 makes the digest a version's identity, so the same tree assembled in a
	// different order has to produce the same bytes.
	reversed := New()
	require.NoError(t, reversed.Add("scripts/run.sh", 0o755, []byte("#!/bin/sh\necho hi\n")))
	require.NoError(t, reversed.Add("plugin.json", 0o644, []byte(`{"name":"demo"}`)))
	require.NoError(t, reversed.Add("skills/demo/SKILL.md", 0o644, []byte("# demo")))

	_, want, _ := packBytes(t, sampleBundle(t))
	_, got, _ := packBytes(t, reversed)
	require.Equal(t, want, got)
}

func TestPackWritesSortedMembersWithZeroedMetadata(t *testing.T) {
	data, _, _ := packBytes(t, sampleBundle(t))

	dec, err := zstd.NewReader(bytes.NewReader(data))
	require.NoError(t, err)
	defer dec.Close()

	tr := tar.NewReader(dec)
	var names []string
	for {
		hdr, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		require.NoError(t, nextErr)
		names = append(names, hdr.Name)
		require.Equal(t, epoch.Unix(), hdr.ModTime.Unix(), "member %q carries an mtime", hdr.Name)
		require.Zero(t, hdr.Uid)
		require.Zero(t, hdr.Gid)
		require.Empty(t, hdr.Uname)
		require.Empty(t, hdr.Gname)
		require.Equal(t, byte(tar.TypeReg), hdr.Typeflag)
	}
	require.Equal(t, []string{"plugin.json", "scripts/run.sh", "skills/demo/SKILL.md"}, names)
}

func TestPackUnpackRoundTrip(t *testing.T) {
	data, _, _ := packBytes(t, sampleBundle(t))

	got, err := Unpack(context.Background(), bytes.NewReader(data), Limits{})
	require.NoError(t, err)

	want := sampleBundle(t)
	require.Equal(t, want.Paths(), got.Paths())
	require.Equal(t, want.TotalBytes(), got.TotalBytes())
	for _, f := range want.Files() {
		gotFile, ok := got.Lookup(f.Path)
		require.True(t, ok, "missing %q", f.Path)
		require.Equal(t, f.Data, gotFile.Data)
		require.Equal(t, f.Mode, gotFile.Mode)
	}
}

func TestPackHandlesLongPaths(t *testing.T) {
	long := strings.Repeat("nested/", 20) + "SKILL.md"
	require.Greater(t, len(long), 100, "the point of this case is a path past the ustar name field")

	b := New()
	require.NoError(t, b.Add(long, 0o644, []byte("x")))

	first, firstDigest, _ := packBytes(t, b)
	_, secondDigest, _ := packBytes(t, b)
	require.Equal(t, firstDigest, secondDigest)

	got, err := Unpack(context.Background(), bytes.NewReader(first), Limits{})
	require.NoError(t, err)
	require.Equal(t, []string{long}, got.Paths())
}

func TestPackEmptyBundle(t *testing.T) {
	data, digest, size := packBytes(t, New())
	require.NotZero(t, size)
	require.NotEqual(t, [32]byte{}, digest)

	got, err := Unpack(context.Background(), bytes.NewReader(data), Limits{})
	require.NoError(t, err)
	require.Zero(t, got.Len())
}

func TestUnpackReappliesCaps(t *testing.T) {
	b := New()
	require.NoError(t, b.Add("big.bin", 0o644, make([]byte, 64<<10)))
	data, _, _ := packBytes(t, b)

	_, err := Unpack(context.Background(), bytes.NewReader(data), Limits{
		MaxEntryBytes:       1024,
		MaxCompressionRatio: 1 << 20,
		RatioGraceBytes:     1 << 20,
	})
	requireKind(t, err, KindTooLarge, CapEntrySize)
}

func TestUnpackRejectsGarbage(t *testing.T) {
	_, err := Unpack(context.Background(), strings.NewReader("not zstd at all"), Limits{})
	require.Error(t, err)
	var be *Error
	require.ErrorAs(t, err, &be)
	require.Equal(t, KindMalformed, be.Kind)
}

func TestBundleAddRejectsDuplicatePath(t *testing.T) {
	b := New()
	require.NoError(t, b.Add("plugin.json", 0o644, []byte("{}")))
	require.ErrorIs(t, b.Add("plugin.json", 0o644, []byte("{}")), ErrDuplicatePath)
	require.Equal(t, 1, b.Len())
}

func TestBundleNormalisesModes(t *testing.T) {
	b := New()
	// setuid, setgid and sticky bits from an archive must not survive into the tree.
	require.NoError(t, b.Add("safe.txt", 0o600, []byte("a")))
	require.NoError(t, b.Add("evil.sh", 0o4777, []byte("b")))

	safe, ok := b.Lookup("safe.txt")
	require.True(t, ok)
	require.Equal(t, FileMode, safe.Mode)

	evil, ok := b.Lookup("evil.sh")
	require.True(t, ok)
	require.Equal(t, ExecMode, evil.Mode)
}

func TestBundleLookupAfterSort(t *testing.T) {
	b := sampleBundle(t)
	require.Equal(t, []string{"plugin.json", "scripts/run.sh", "skills/demo/SKILL.md"}, b.Paths())
	require.True(t, b.Has("scripts/run.sh"))
	require.False(t, b.Has("nope"))
	require.NoError(t, b.Add("zzz.txt", 0o644, []byte("z")))
	got, ok := b.Lookup("plugin.json")
	require.True(t, ok)
	require.Equal(t, `{"name":"demo"}`, string(got.Data))
}

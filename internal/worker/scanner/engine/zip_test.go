package engine

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/bundle"
)

// tree is a Tree built from a map, standing in for *checks.Bundle.
type tree map[string][]byte

func (t tree) Paths() []string {
	out := make([]string, 0, len(t))
	for path := range t {
		out = append(out, path)
	}
	// Sorted, because zipTree writes members in the order it is given and the
	// request bytes are asserted below.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func (t tree) File(path string) (bundle.File, bool) {
	data, ok := t[path]
	if !ok {
		return bundle.File{}, false
	}
	return bundle.File{Path: path, Mode: 0o755, Data: data}, true
}

func TestZipTree(t *testing.T) {
	t.Run("members are serialised non-executable whatever the publisher shipped", func(t *testing.T) {
		// The engine reads content. An executable bit it never looks at is a bit
		// not worth carrying into another process's temp directory.
		packed, err := zipTree(tree{"setup.sh": []byte("#!/bin/sh\necho hi\n")})
		require.NoError(t, err)

		reader, err := zip.NewReader(bytes.NewReader(packed), int64(len(packed)))
		require.NoError(t, err)
		require.Len(t, reader.File, 1)
		require.Equal(t, fs.FileMode(0o644), reader.File[0].Mode().Perm())
		require.Zero(t, reader.File[0].Mode()&0o111)
	})

	t.Run("the same tree packs to the same bytes", func(t *testing.T) {
		subject := tree{"a.md": []byte("one"), "b.md": []byte("two")}
		first, err := zipTree(subject)
		require.NoError(t, err)
		second, err := zipTree(subject)
		require.NoError(t, err)
		require.Equal(t, first, second)
	})

	t.Run("an empty tree is refused rather than sent", func(t *testing.T) {
		_, err := zipTree(tree{})
		require.Error(t, err)
		_, err = zipTree(nil)
		require.Error(t, err)
	})

	t.Run("a tree past the engine's entry cap is over cap, not a request", func(t *testing.T) {
		// This project extracts up to 10 000 entries and the engine's upload
		// endpoint takes 500, compiled in rather than configurable. A package
		// between the two is a blind spot the caller records, not a failure.
		big := tree{}
		for i := 0; i <= maxEntries; i++ {
			big[fmt.Sprintf("f%05d.md", i)] = []byte("x")
		}
		_, err := zipTree(big)
		require.ErrorIs(t, err, ErrOverCap)
	})

	t.Run("a tree past the uncompressed cap is over cap", func(t *testing.T) {
		_, err := zipTree(tree{"big.bin": make([]byte, maxUncompressedBytes+1)})
		require.ErrorIs(t, err, ErrOverCap)
	})
}

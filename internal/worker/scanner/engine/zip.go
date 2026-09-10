package engine

import (
	"archive/zip"
	"bytes"
	"fmt"
	"time"

	"agent-manager/internal/bundle"
)

// Tree is the extracted, already-capped file tree the engine analyses.
// *checks.Bundle satisfies it.
type Tree interface {
	Paths() []string
	File(path string) (bundle.File, bool)
}

// The engine's upload endpoint refuses past these, and they are compiled into
// it rather than configurable. This project's own extraction caps are looser
// (10 000 entries, 250 MB), so a tree can be valid here and still be one the
// engine will not take.
const (
	maxUploadBytes       = 50 << 20
	maxEntries           = 500
	maxUncompressedBytes = 200 << 20
)

// zipEpoch is the mtime written for every member. The engine reads content,
// not timestamps, and a fixed one keeps the request bytes reproducible.
var zipEpoch = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// zipMode is written for every member. The tree is serialised
// non-executable regardless of what the publisher shipped: the engine has no
// reason to execute anything, and a bit it never reads is a bit not worth
// carrying.
const zipMode = 0o644

// zipTree serialises a tree for the engine's upload endpoint. It returns
// ErrOverCap rather than a request the engine is certain to refuse.
func zipTree(tree Tree) ([]byte, error) {
	if tree == nil {
		return nil, fmt.Errorf("engine: no tree")
	}

	paths := tree.Paths()
	if len(paths) == 0 {
		return nil, fmt.Errorf("engine: tree has no files")
	}
	if len(paths) > maxEntries {
		return nil, fmt.Errorf("%w: %d files against a limit of %d",
			ErrOverCap, len(paths), maxEntries)
	}

	var total int64
	for _, path := range paths {
		file, ok := tree.File(path)
		if !ok {
			continue
		}
		total += int64(len(file.Data))
	}
	if total > maxUncompressedBytes {
		return nil, fmt.Errorf("%w: %d uncompressed bytes against a limit of %d",
			ErrOverCap, total, maxUncompressedBytes)
	}

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, path := range paths {
		file, ok := tree.File(path)
		if !ok {
			continue
		}
		header := &zip.FileHeader{Name: path, Method: zip.Deflate, Modified: zipEpoch}
		header.SetMode(zipMode)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			return nil, fmt.Errorf("engine: add %s to the request archive: %w", path, err)
		}
		if _, err := entry.Write(file.Data); err != nil {
			return nil, fmt.Errorf("engine: write %s into the request archive: %w", path, err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("engine: finish the request archive: %w", err)
	}

	if buf.Len() > maxUploadBytes {
		return nil, fmt.Errorf("%w: %d compressed bytes against a limit of %d",
			ErrOverCap, buf.Len(), maxUploadBytes)
	}
	return buf.Bytes(), nil
}

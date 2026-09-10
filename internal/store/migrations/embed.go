// Package migrations embeds the versioned SQL Atlas generates from
// internal/store/schema, so anything that needs the schema replays exactly
// the files checked in rather than a second description of them. Apply takes
// a function rather than a database handle: this package stays free of pgx,
// bun and database/sql so nothing can start depending on it for a connection.
package migrations

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed *.sql
var files embed.FS

// File is one migration in apply order.
type File struct {
	Name string
	SQL  string
}

// Files returns every migration in the order Atlas applies them, which is
// lexicographic by the version prefix in the filename.
func Files() ([]File, error) {
	entries, err := fs.Glob(files, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(entries)

	out := make([]File, 0, len(entries))
	for _, name := range entries {
		b, err := files.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", name, err)
		}
		out = append(out, File{Name: name, SQL: string(b)})
	}
	return out, nil
}

// Apply replays every migration through exec, in order. exec must run a
// multi-statement script: the migrations contain do-blocks whose bodies are
// dollar-quoted, so splitting on semicolons would corrupt them.
func Apply(ctx context.Context, exec func(context.Context, string) error) error {
	all, err := Files()
	if err != nil {
		return err
	}
	for _, f := range all {
		if strings.TrimSpace(f.SQL) == "" {
			continue
		}
		if err := exec(ctx, f.SQL); err != nil {
			return fmt.Errorf("apply migration %s: %w", f.Name, err)
		}
	}
	return nil
}

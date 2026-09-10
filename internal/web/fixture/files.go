package fixture

import (
	"context"

	"agent-manager/internal/web/view"
)

// The files panel's half of the fixture (US3/US5: read a skill's files
// before using it). Only the packages named below have anything to show —
// absent from the map is a legitimate, already-handled state (an empty
// files panel), not an omission to fill in.

type fixtureFile struct {
	path, kind, size, content string
}

var fixtureFiles = map[string][]fixtureFile{
	"example/adr-writer": {
		{path: "SKILL.md", kind: "markdown", size: "612 B", content: "# ADR writer\n\n" +
			"Writes and supersedes architecture decision records in the house format.\n\n" +
			"## Usage\n\n1. Run `/adr new <title>`.\n2. Fill in the context and decision sections.\n" +
			"3. Link the superseded record, if any.\n"},
		{path: "references/template.md", kind: "markdown", size: "84 B",
			content: "# Template\n\nContext, decision, consequences.\n"},
	},
	"example/platform-toolkit": {
		{path: "plugin.json", kind: "text", size: "218 B", content: `{"name":"platform-toolkit","version":"1.3.0"}`},
		{path: "skills/adr-writer/SKILL.md", kind: "markdown", size: "612 B",
			content: "# ADR writer\n\nBundled here; see example/adr-writer for the standalone skill.\n"},
	},
}

// fixtureFilesDefault picks SKILL.md over plugin.json, exactly as
// listPackageFiles does: a plugin whose OWN root carries no SKILL.md still
// opens on its manifest, but a root SKILL.md always wins.
func fixtureFilesDefault(files []fixtureFile) string {
	for _, candidate := range []string{"SKILL.md", "plugin.json"} {
		for _, f := range files {
			if f.path == candidate {
				return candidate
			}
		}
	}
	return ""
}

// PackageFiles implements web.PackageFileSource's list half.
func (c *Catalog) PackageFiles(_ context.Context, namespace, name string) (view.FileList, error) {
	files, ok := fixtureFiles[namespace+"/"+name]
	if !ok {
		return view.FileList{}, nil
	}
	list := view.FileList{Default: fixtureFilesDefault(files)}
	for _, f := range files {
		list.Files = append(list.Files, view.FileRow{Path: f.path, Kind: f.kind, SizeLabel: f.size})
	}
	return list, nil
}

// PackageFile implements web.PackageFileSource's content half.
func (c *Catalog) PackageFile(_ context.Context, namespace, name, path string) (view.FileDetail, error) {
	for _, f := range fixtureFiles[namespace+"/"+name] {
		if f.path != path {
			continue
		}
		detail := view.FileDetail{Path: f.path, Kind: f.kind, Text: f.content}
		if f.kind == "markdown" {
			detail.Markdown = view.ParseMarkdown([]byte(f.content))
		}
		return detail, nil
	}
	return view.FileDetail{}, view.ErrNotFound
}

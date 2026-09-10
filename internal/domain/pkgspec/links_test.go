package pkgspec_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/bundle"
	"agent-manager/internal/domain/pkgspec"
)

// A forge tarball of a real repository, which is where this came from: one
// unpredictable wrapper directory, a symlink at the repository root, and the
// package the caller asked for in a subdirectory the link is nowhere near.
//
// github.com/mattpocock/skills is the case that found it. Its AGENTS.md is a
// symlink, and refusing the archive over a member made every version of that
// repository permanently unimportable — including a request for
// skills/engineering/code-review, which contains no link at all.
func forgeTarball(t *testing.T, members ...tarMember) *bundle.Bundle {
	t.Helper()

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for i := range members {
		member := &members[i]
		hdr := member.header
		hdr.Size = int64(len(member.body))
		if hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
			hdr.Mode = 0o644
		}
		require.NoError(t, tw.WriteHeader(&hdr))
		_, err := tw.Write([]byte(member.body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	tree, err := bundle.ExtractTarGz(context.Background(), bytes.NewReader(raw.Bytes()), bundle.Limits{})
	require.NoError(t, err, "the archive was refused, so no version of this repository can be imported")
	return tree
}

type tarMember struct {
	header tar.Header
	body   string
}

func link(name, target string) tarMember {
	return tarMember{header: tar.Header{Typeflag: tar.TypeSymlink, Name: name, Linkname: target}}
}

func file(name, body string) tarMember {
	return tarMember{header: tar.Header{Name: name}, body: body}
}

const skillManifest = "---\nname: code-review\ndescription: Reviews a diff.\n---\n"

func TestALinkOutsideThePackageRootIsNotThisPackagesProblem(t *testing.T) {
	const wrapper = "mattpocock-skills-835450e/"
	const root = wrapper + "skills/engineering/code-review"

	tree := forgeTarball(t,
		link(wrapper+"AGENTS.md", "skills/engineering/code-review/SKILL.md"),
		file(root+"/SKILL.md", skillManifest),
		file(root+"/scripts/review.sh", "#!/bin/sh\ngit diff\n"),
	)

	pkg, err := pkgspec.Inspect(tree, root)
	require.NoError(t, err)

	require.Equal(t, []string{"SKILL.md", "scripts/review.sh"}, pkg.Files.Paths())
	require.Empty(t, pkg.Layout.Links,
		"a link elsewhere in the archive was reported against this package, which sends a reader looking in the wrong place")
	require.Empty(t, pkg.Layout.Dropped)
}

func TestALinkInsideThePackageRootIsReported(t *testing.T) {
	// Here the missing path is the package's own, so saying nothing would leave
	// someone to work out on their own why a file they can see in the
	// repository is not in the stored version.
	tree := forgeTarball(t,
		file("SKILL.md", skillManifest),
		link("scripts/review.sh", "../../shared/review.sh"),
	)

	pkg, err := pkgspec.Inspect(tree, ".")
	require.NoError(t, err)

	require.Equal(t, []string{"scripts/review.sh"}, pkg.Layout.Links)
	require.NotContains(t, pkg.Files.Paths(), "scripts/review.sh")

	t.Run("and the panel lists it as a link rather than as outside the layout", func(t *testing.T) {
		notes := make(map[string]string, len(pkg.Layout.Entries))
		for _, entry := range pkg.Layout.Entries {
			notes[entry.Path] = entry.Note
		}
		require.Equal(t, "link, not stored", notes["scripts/"])
	})
}

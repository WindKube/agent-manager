package deliver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const codexBefore = `# my codex config
model = "gpt-5" # keep me

[mcp_servers.mine]
command = "my-server"   # hand-tuned
args = ["--x"]

# notes for the profile below
[profiles.work]
model = "o3"
`

const ghTable = `[mcp_servers.kit-gh]
command = "npx"
args = ["-y", "gh-mcp"]
env = { "TOKEN" = "abc" }
`

func TestATOMLTableIsAppendedReplacedAndRemovedLeavingTheRestByteForByte(t *testing.T) {
	added, err := tomlSetTable([]byte(codexBefore), "kit-gh", []byte(ghTable))
	require.NoError(t, err)
	require.Equal(t, codexBefore+"\n"+ghTable, string(added))

	again, err := tomlSetTable(added, "kit-gh", []byte(ghTable))
	require.NoError(t, err)
	require.Equal(t, string(added), string(again), "setting the same table twice is a no-op")

	v2 := "[mcp_servers.kit-gh]\ncommand = \"npx\"\nargs = [\"-y\", \"gh-mcp@2\"]\n"
	replaced, err := tomlSetTable(added, "kit-gh", []byte(v2))
	require.NoError(t, err)
	require.Equal(t, codexBefore+"\n"+v2, string(replaced))

	removed, err := tomlRemoveTable(replaced, "kit-gh")
	require.NoError(t, err)
	require.Equal(t, codexBefore, string(removed), "add then remove restores the file")
}

func TestATOMLTableInTheMiddleKeepsTheCommentsOfTheNextTable(t *testing.T) {
	doc := "[mcp_servers.kit-gh]\ncommand = \"old\"\n[mcp_servers.kit-gh.env]\nA = \"1\"\n\n# about profiles\n[profiles.work]\nmodel = \"o3\"\n"
	out, err := tomlSetTable([]byte(doc), "kit-gh", []byte(ghTable))
	require.NoError(t, err)
	require.Equal(t, ghTable+"\n# about profiles\n[profiles.work]\nmodel = \"o3\"\n", string(out))

	gone, err := tomlRemoveTable([]byte(doc), "kit-gh")
	require.NoError(t, err)
	require.Equal(t, "\n# about profiles\n[profiles.work]\nmodel = \"o3\"\n", string(gone))
}

func TestATOMLEntryAmctlCannotEditAsATableIsRefused(t *testing.T) {
	doc := "[mcp_servers]\nkit-gh = { command = \"x\" }\n"
	_, err := tomlSetTable([]byte(doc), "kit-gh", []byte(ghTable))
	require.ErrorContains(t, err, "does not edit")
	_, err = tomlRemoveTable([]byte(doc), "kit-gh")
	require.ErrorContains(t, err, "does not edit")

	_, err = tomlSetTable([]byte("model = \n"), "kit-gh", []byte(ghTable))
	require.Error(t, err, "a file that does not parse is never edited")
}

func TestATOMLHeaderInsideAMultilineStringIsNotATable(t *testing.T) {
	doc := "notes = \"\"\"\n[mcp_servers.kit-gh]\n\"\"\"\n"
	out, err := tomlSetTable([]byte(doc), "kit-gh", []byte(ghTable))
	require.NoError(t, err)
	require.Equal(t, doc+"\n"+ghTable, string(out))
}

func TestTOMLStringsRoundTrip(t *testing.T) {
	for _, s := range []string{`plain`, `with "quotes" and \back`, "tab\tnew\nline", "ctl\x01", "ünïcode"} {
		m, err := parseTOML([]byte("k = " + tomlString(s) + "\n"))
		require.NoError(t, err, s)
		require.Equal(t, s, m["k"])
	}
}

const openCodeBefore = `{
  // my comment
  "$schema": "https://opencode.ai/config.json",
  "theme": "x", // trailing
  "mcp": {
    "mine": {"type": "local", "command": ["a"]},
  },
}
`

var ocEntry = map[string]any{"type": "local", "command": []string{"npx", "-y"}, "enabled": true}

func TestAJSONCMemberIsAddedReplacedAndRemovedLeavingTheRestByteForByte(t *testing.T) {
	added, err := jsoncSet([]byte(openCodeBefore), ocEntry, "mcp", "kit-gh")
	require.NoError(t, err)
	require.Equal(t, `{
  // my comment
  "$schema": "https://opencode.ai/config.json",
  "theme": "x", // trailing
  "mcp": {
    "mine": {"type": "local", "command": ["a"]},
    "kit-gh": {
      "command": [
        "npx",
        "-y"
      ],
      "enabled": true,
      "type": "local"
    },
  },
}
`, string(added))

	got, err := jsoncGet(added, "mcp", "kit-gh")
	require.NoError(t, err)
	require.Equal(t, roundTrip(ocEntry), got)

	again, err := jsoncSet(added, ocEntry, "mcp", "kit-gh")
	require.NoError(t, err)
	require.Equal(t, string(added), string(again))

	removed, err := jsoncRemove(added, "mcp", "kit-gh")
	require.NoError(t, err)
	require.Equal(t, openCodeBefore, string(removed))
}

func TestAJSONCFileWithoutAnMCPObjectGetsOneAndLosesItAgain(t *testing.T) {
	for _, before := range []string{"{\n  \"theme\": \"x\"\n}\n", "{\n\t\"theme\": \"x\", // c\n}\n", "{}\n", ""} {
		added, err := jsoncSet([]byte(before), ocEntry, "mcp", "kit-gh")
		require.NoError(t, err, before)
		got, err := jsoncGet(added, "mcp", "kit-gh")
		require.NoError(t, err)
		require.Equal(t, roundTrip(ocEntry), got)

		removed, err := jsoncRemove(added, "mcp", "kit-gh")
		require.NoError(t, err)
		if before == "" {
			before = "{}\n"
		}
		require.Equal(t, before, string(removed), "%q -> %q", before, added)
	}
}

func TestAJSONCFileThatIsNotAnObjectIsRefused(t *testing.T) {
	_, err := jsoncSet([]byte("[1]"), ocEntry, "mcp", "kit-gh")
	require.Error(t, err)
	_, err = jsoncSet([]byte(`{"mcp": 3}`), ocEntry, "mcp", "kit-gh")
	require.Error(t, err)
	_, err = jsoncSet([]byte(`{"mcp": {`), ocEntry, "mcp", "kit-gh")
	require.Error(t, err)
}

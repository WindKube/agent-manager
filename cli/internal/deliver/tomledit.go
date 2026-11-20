package deliver

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
)

// Codex's config.toml is edited as text, one [mcp_servers.<key>] table at a
// time: comments, ordering and formatting elsewhere stay byte for byte. Every
// edit is re-parsed and must change exactly that one table, or it is refused.

const codexServersTable = "mcp_servers"

func parseTOML(doc []byte) (map[string]any, error) {
	m := map[string]any{}
	if err := toml.Unmarshal(doc, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// tomlTable returns the value at mcp_servers.<key>, nil when absent.
func tomlTable(doc map[string]any, key string) any {
	servers, _ := doc[codexServersTable].(map[string]any)
	return servers[key]
}

func tomlSetTable(doc []byte, key string, block []byte) ([]byte, error) {
	before, err := parseTOML(doc)
	if err != nil {
		return nil, err
	}
	entry, err := parseTOML(block)
	if err != nil {
		return nil, fmt.Errorf("internal: rendered table does not parse: %w", err)
	}

	lines := splitLines(string(doc))
	start, end, found := findTOMLTable(lines, key)
	var out string
	switch {
	case found:
		out = strings.Join(lines[:start], "") + string(block) + strings.Join(lines[end:], "")
	case tomlTable(before, key) != nil:
		return nil, fmt.Errorf("[%s.%s] is defined in a form amctl does not edit (not its own table)", codexServersTable, key)
	default:
		text := string(doc)
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		if text != "" {
			text += "\n"
		}
		out = text + string(block)
	}

	want := cloneMap(before)
	servers, _ := want[codexServersTable].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
		want[codexServersTable] = servers
	}
	servers[key] = tomlTable(entry, key)
	return checkTOML(out, want)
}

func tomlRemoveTable(doc []byte, key string) ([]byte, error) {
	before, err := parseTOML(doc)
	if err != nil {
		return nil, err
	}
	lines := splitLines(string(doc))
	start, end, found := findTOMLTable(lines, key)
	if !found {
		if tomlTable(before, key) != nil {
			return nil, fmt.Errorf("[%s.%s] is defined in a form amctl does not edit (not its own table)", codexServersTable, key)
		}
		return doc, nil
	}
	if start > 0 && blank(lines[start-1]) && (end == len(lines) || blank(lines[end])) {
		start--
	}
	out := strings.Join(lines[:start], "") + strings.Join(lines[end:], "")

	want := cloneMap(before)
	if servers, ok := want[codexServersTable].(map[string]any); ok {
		delete(servers, key)
	}
	return checkTOML(out, want)
}

func checkTOML(out string, want map[string]any) ([]byte, error) {
	got, err := parseTOML([]byte(out))
	if err != nil {
		return nil, fmt.Errorf("the edited file would not parse: %w", err)
	}
	dropEmptyServers(got)
	dropEmptyServers(want)
	if !reflect.DeepEqual(got, want) {
		return nil, errors.New("the edit would change more than its own table; edit the file by hand")
	}
	return []byte(out), nil
}

func dropEmptyServers(m map[string]any) {
	if s, ok := m[codexServersTable].(map[string]any); ok && len(s) == 0 {
		delete(m, codexServersTable)
	}
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			v = cloneMap(sub)
		}
		out[k] = v
	}
	return out
}

func splitLines(s string) []string {
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// findTOMLTable returns the line range of [mcp_servers.<key>] and its own
// sub-tables, without the blank and comment lines that lead into the next
// table.
func findTOMLTable(lines []string, key string) (start, end int, found bool) {
	own := []string{codexServersTable, key}
	start = -1
	inString := ""
	for i, line := range lines {
		if inString != "" {
			if strings.Count(line, inString)%2 == 1 {
				inString = ""
			}
			continue
		}
		for _, q := range []string{`"""`, `'''`} {
			if strings.Count(line, q)%2 == 1 {
				inString = q
			}
		}
		path, isHeader := tomlHeader(line)
		if !isHeader {
			continue
		}
		mine := len(path) >= len(own) && slices.Equal(path[:len(own)], own)
		switch {
		case start < 0 && mine && len(path) == len(own):
			start = i
		case start >= 0 && !mine:
			return start, trimTail(lines, start, i), true
		}
	}
	if start < 0 {
		return 0, 0, false
	}
	return start, trimTail(lines, start, len(lines)), true
}

func trimTail(lines []string, start, end int) int {
	for end > start+1 {
		t := strings.TrimSpace(lines[end-1])
		if t != "" && !strings.HasPrefix(t, "#") {
			break
		}
		end--
	}
	return end
}

func blank(line string) bool { return strings.TrimSpace(line) == "" }

// tomlHeader parses a standard table header line into its key path; array
// tables come back with a nil path, which matches nothing.
func tomlHeader(line string) ([]string, bool) {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "[") {
		return nil, false
	}
	if strings.HasPrefix(s, "[[") {
		return nil, true
	}
	var path []string
	rest := strings.TrimLeft(s[1:], " \t")
	for {
		var part string
		switch {
		case strings.HasPrefix(rest, `"`):
			end := closingQuote(rest)
			if end < 0 {
				return nil, false
			}
			v, err := strconv.Unquote(rest[:end+1])
			if err != nil {
				return nil, false
			}
			part, rest = v, rest[end+1:]
		case strings.HasPrefix(rest, "'"):
			end := strings.IndexByte(rest[1:], '\'')
			if end < 0 {
				return nil, false
			}
			part, rest = rest[1:end+1], rest[end+2:]
		default:
			n := 0
			for n < len(rest) && bareKeyChar(rest[n]) {
				n++
			}
			if n == 0 {
				return nil, false
			}
			part, rest = rest[:n], rest[n:]
		}
		path = append(path, part)
		rest = strings.TrimLeft(rest, " \t")
		switch {
		case strings.HasPrefix(rest, "."):
			rest = strings.TrimLeft(rest[1:], " \t")
		case strings.HasPrefix(rest, "]"):
			return path, true
		default:
			return nil, false
		}
	}
}

func closingQuote(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}

func bareKeyChar(c byte) bool {
	return c == '_' || c == '-' || ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

// tomlString renders a TOML basic string.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f || r == utf8.RuneError:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func tomlStringArray(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = tomlString(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func tomlInlineTable(m map[string]string) string {
	keys := sortedKeys(m)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = tomlString(k) + " = " + tomlString(m[k])
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

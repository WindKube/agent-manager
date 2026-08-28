package capability

import (
	"bytes"
	"encoding/json"
	"fmt"

	"agent-manager/internal/domain/pkgspec"
)

// Expected is T057: the capability set the publisher recorded, read out of a
// stored `version.manifest` (FR-018a).
//
// It returns rows. It does not write them — the scanner does, in the transaction
// that records the scan (T071), because `am_fetcher` holds no grant on
// `capability` and deliberately never gets one. Until a version has been scanned
// it therefore has no rows of EITHER source, which is why the detail panel needs
// a "not scanned yet" state rather than an empty comparison.
//
// Nothing here is an enforced permission. An expectation is a claim to compare
// the inferred set against (FR-027), and where the inferred set exceeds it a
// finding is raised — by the scanner, not by this function.
//
// A nil result with a nil error is the normal case: FR-018a says a publisher MAY
// record an expected set, and "recorded nothing" is exactly the case where every
// discovered host is surfaced for review rather than silently accepted.
func Expected(manifest []byte) ([]Capability, error) {
	raw, ok, err := extensionObject(manifest)
	if err != nil || !ok {
		return nil, err
	}

	// DisallowUnknownFields inside our OWN namespace, matching
	// pkgspec.Plugin.AgentManager. The published schemas assign no semantics to a
	// namespace object's contents, so nothing else checks this: a misspelled
	// `expectedCapabilties` would otherwise be an expectation that silently does
	// not exist, and the finding it was meant to suppress would never appear.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var ext pkgspec.AgentManagerExtension
	if err := decoder.Decode(&ext); err != nil {
		return nil, fmt.Errorf("read %s from the manifest: %w", pkgspec.ExtensionNamespace, err)
	}

	rows := make([]Capability, 0, len(ext.ExpectedCapabilities))
	for _, declared := range ext.ExpectedCapabilities {
		row, err := expectedRow(declared)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return order(rows), nil
}

func expectedRow(declared pkgspec.ExpectedCapability) (Capability, error) {
	if !known(declared.Name) {
		// Fail closed rather than dropping the row. An unrecognised name can never
		// match anything Infer produces, so keeping it would put an expectation on
		// the page that suppresses nothing and reads as though it does.
		return Capability{}, fmt.Errorf("expected capability %q is not one of %v",
			declared.Name, Names)
	}

	level := Level(declared.Level)
	if declared.Level == "" {
		// FR-018a records an expectation, and the safe reading of one that names no
		// level is the one that asks for a human rather than the one that does not.
		level = LevelReview
	}
	if !level.Valid() {
		return Capability{}, fmt.Errorf("expected capability %q has level %q, which is not one of %s, %s, %s",
			declared.Name, declared.Level, LevelScoped, LevelAllowlisted, LevelReview)
	}

	return finish(Capability{
		Name:   declared.Name,
		Source: SourceExpected,
		Level:  level,
		Detail: declared.Detail,
	}), nil
}

// extensionObject finds this project's namespace object in a stored manifest.
//
// TWO places are looked at, because the two specifications name their free-form
// namespace object differently and a package has only the one its own spec
// allows. Agent Plugins 1.0.0 has `extensions`, which FR-018a names. Agent Skills
// frontmatter has no `extensions` key at all — `additionalProperties: false`
// refuses one — and offers `metadata` instead. Reading only `extensions` would
// mean a standalone skill could never record an expected set, and FR-027's "no
// expected set, so surface every host" would be permanent for every skill in the
// catalog rather than a state a publisher can leave.
//
// Both are keyed by the same reverse-domain name, so this is one expectation
// with two spec-sanctioned homes, not two competing conventions.
func extensionObject(manifest []byte) (json.RawMessage, bool, error) {
	if len(bytes.TrimSpace(manifest)) == 0 {
		return nil, false, nil
	}

	var doc struct {
		Extensions map[string]json.RawMessage `json:"extensions"`
		Metadata   map[string]json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(manifest, &doc); err != nil {
		return nil, false, fmt.Errorf("read the stored manifest: %w", err)
	}

	for _, namespace := range []map[string]json.RawMessage{doc.Extensions, doc.Metadata} {
		raw, ok := namespace[pkgspec.ExtensionNamespace]
		if ok && len(bytes.TrimSpace(raw)) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return raw, true, nil
		}
	}
	return nil, false, nil
}

func known(name string) bool {
	for _, candidate := range Names {
		if candidate == name {
			return true
		}
	}
	return false
}

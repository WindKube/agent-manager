package capability

import (
	"bytes"
	"encoding/json"
	"fmt"

	"agent-manager/internal/domain/pkgspec"
)

// Expected is the capability set the publisher recorded, read out of a
// stored `version.manifest`. It returns rows; it does not write them (the
// scanner does, in the transaction that records the scan), so until a
// version has been scanned there are rows of neither source.
//
// A nil result with a nil error is the normal case: a publisher may record
// no expected set, in which case every discovered host is surfaced for
// review rather than silently accepted.
func Expected(manifest []byte) ([]Capability, error) {
	raw, ok, err := extensionObject(manifest)
	if err != nil || !ok {
		return nil, err
	}

	// DisallowUnknownFields: nothing else checks this namespace object's
	// contents, so a misspelled field would otherwise silently vanish.
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
		// Fail closed rather than dropping the row: an unrecognised name can
		// never match anything Infer produces.
		return Capability{}, fmt.Errorf("expected capability %q is not one of %v",
			declared.Name, Names)
	}

	level := Level(declared.Level)
	if declared.Level == "" {
		// No level named: the safe reading asks for a human.
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

// extensionObject looks in two places: Agent Plugins' `extensions` and
// Agent Skills' `metadata`, since the two specs name their free-form
// namespace object differently and a standalone skill has no `extensions`
// key at all. Both are keyed by the same reverse-domain name.
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

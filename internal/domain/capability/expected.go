package capability

import (
	"bytes"
	"encoding/json"
	"fmt"

	"agent-manager/internal/domain/pkgspec"
)

// Expected reads the publisher's capability set from a stored
// `version.manifest`. Nil with no error means none was recorded.
func Expected(manifest []byte) ([]Capability, error) {
	raw, ok, err := extensionObject(manifest)
	if err != nil || !ok {
		return nil, err
	}

	// Nothing else checks this object, so a misspelled field would vanish.
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
		// Fail closed: an unrecognised name can never match an inferred row.
		return Capability{}, fmt.Errorf("expected capability %q is not one of %v",
			declared.Name, Names)
	}

	level := Level(declared.Level)
	if declared.Level == "" {
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

// extensionObject checks Agent Plugins' `extensions` and Agent Skills'
// `metadata`, both keyed by the same namespace.
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

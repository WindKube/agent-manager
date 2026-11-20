package audit_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"agent-manager/internal/store/audit"
	"agent-manager/internal/store/models"
)

func entry(subject audit.Subject) audit.Entry {
	return audit.Entry{
		Kind: models.AuditKindFetch, Action: "stored", Actor: "fetcher", ActorKind: models.ActorKindSystem,
		Text: "stored example/a@1.0.0", Source: "system", Subject: subject,
	}
}

func TestNewCarriesTheSubjectIntoTheRow(t *testing.T) {
	e := entry(audit.Version("example", "a", "1.0.0"))
	e.Data = map[string]any{"digest": "sha256:ab"}

	event, err := audit.New(e)
	require.NoError(t, err)
	require.Equal(t, models.AuditSubjectVersion, event.SubjectKind)
	require.Equal(t, "example/a@1.0.0", event.SubjectID)
	require.Equal(t, "example", event.Namespace)
	require.Equal(t, map[string]any{
		"action": "stored", "name": "a", "semver": "1.0.0",
		"package": "example/a", "digest": "sha256:ab",
	}, event.Data)
	require.Equal(t, e.Text, event.Text)
}

func TestNewRefusesARowWithoutASubjectOrAction(t *testing.T) {
	for name, e := range map[string]audit.Entry{
		"no subject":     entry(audit.Subject{}),
		"no subject id":  entry(audit.Mapping("")),
		"unknown kind":   entry(audit.Subject{Kind: "spaceship", ID: "x"}),
		"no action":      func() audit.Entry { e := entry(audit.Policy()); e.Action = ""; return e }(),
		"bad audit kind": func() audit.Entry { e := entry(audit.Policy()); e.Kind = "nope"; return e }(),
		"data overwrites": func() audit.Entry {
			e := entry(audit.Profile(uuid.New(), "p"))
			e.Data = map[string]any{"slug": "q"}
			return e
		}(),
		"data sets action": func() audit.Entry {
			e := entry(audit.Policy())
			e.Data = map[string]any{"action": "x"}
			return e
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := audit.New(e)
			require.Error(t, err)
		})
	}
}

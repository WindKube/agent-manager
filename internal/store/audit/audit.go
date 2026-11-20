// Package audit builds audit_event rows. Every write goes through New, so
// none lands without a subject.
package audit

import (
	"errors"
	"fmt"
	"maps"
	"strconv"

	"github.com/google/uuid"

	"agent-manager/internal/store/models"
)

// Subject is what an audit row is about. Build one with the constructors
// below, so the subject_id shape and the data keys stay one per kind.
//
// Data keys a subject contributes:
//
//	package   name
//	version   name, semver, package (namespace/name)
//	finding   name, semver, package (namespace/name), ruleId
//	profile   slug
//	revision  profile (slug), profileId, revision (seq)
//	category  name (absent on delete, which knows only the id)
//	device    host
//	service-token  name
//	machine   host
type Subject struct {
	Kind      models.AuditSubjectKind
	ID        string
	Namespace string
	Data      map[string]any
}

func Package(namespace, name string) Subject {
	return Subject{Kind: models.AuditSubjectPackage, ID: namespace + "/" + name, Namespace: namespace,
		Data: map[string]any{"name": name}}
}

func Version(namespace, name, semver string) Subject {
	pkg := namespace + "/" + name
	return Subject{Kind: models.AuditSubjectVersion, ID: pkg + "@" + semver, Namespace: namespace,
		Data: map[string]any{"name": name, "semver": semver, "package": pkg}}
}

func Finding(id uuid.UUID, namespace, name, semver, ruleID string) Subject {
	return Subject{Kind: models.AuditSubjectFinding, ID: id.String(), Namespace: namespace,
		Data: map[string]any{"name": name, "semver": semver, "package": namespace + "/" + name, "ruleId": ruleID}}
}

func Profile(id uuid.UUID, slug string) Subject {
	return Subject{Kind: models.AuditSubjectProfile, ID: id.String(), Data: map[string]any{"slug": slug}}
}

func Revision(id, profileID uuid.UUID, slug string, seq int) Subject {
	return Subject{Kind: models.AuditSubjectRevision, ID: id.String(),
		Data: map[string]any{"profile": slug, "profileId": profileID.String(), "revision": seq}}
}

func Category(id, name string) Subject {
	data := map[string]any{}
	if name != "" {
		data["name"] = name
	}
	return Subject{Kind: models.AuditSubjectCategory, ID: id, Data: data}
}

func Mapping(groupName string) Subject {
	return Subject{Kind: models.AuditSubjectMapping, ID: groupName}
}

func Policy() Subject {
	return Subject{Kind: models.AuditSubjectPolicy, ID: strconv.Itoa(int(models.OrgPolicySingletonID))}
}

func Identity(id uuid.UUID) Subject {
	return Subject{Kind: models.AuditSubjectIdentity, ID: id.String()}
}

func Device(id uuid.UUID, host string) Subject {
	return Subject{Kind: models.AuditSubjectDevice, ID: id.String(), Data: map[string]any{"host": host}}
}

func Machine(id uuid.UUID, host string) Subject {
	return Subject{Kind: models.AuditSubjectMachine, ID: id.String(), Data: map[string]any{"host": host}}
}

func ServiceToken(id uuid.UUID, name string) Subject {
	return Subject{Kind: models.AuditSubjectToken, ID: id.String(), Data: map[string]any{"name": name}}
}

// Entry is one audit row to be written. Action is the machine-readable verb
// (`registered`, `stored`, `scanned`, `deleted`, ...) that audit_kind is too
// coarse to carry; it lands in data.action. Data holds the event's own keys
// on top of the subject's: identifiers, versions, verdicts, never a secret or
// a free-form note.
type Entry struct {
	Kind      models.AuditKind
	Action    string
	Actor     string
	ActorKind models.ActorKind
	Text      string
	Source    string
	Subject   Subject
	Data      map[string]any
}

// New builds the row for e, refusing one without a subject; the database's
// audit_event_subject_required check backs it up.
func New(e Entry) (*models.AuditEvent, error) {
	switch {
	case !e.Kind.Valid():
		return nil, fmt.Errorf("audit kind %q is not a value the schema allows", e.Kind)
	case !e.ActorKind.Valid():
		return nil, fmt.Errorf("actor kind %q is not a value the schema allows", e.ActorKind)
	case !e.Subject.Kind.Valid():
		return nil, fmt.Errorf("audit subject kind %q is not a value the schema allows", e.Subject.Kind)
	case e.Subject.ID == "":
		return nil, errors.New("an audit row needs a subject id")
	case e.Action == "":
		return nil, errors.New("an audit row needs an action")
	}

	data := make(map[string]any, len(e.Subject.Data)+len(e.Data)+1)
	maps.Copy(data, e.Subject.Data)
	for k, v := range e.Data {
		if _, clash := data[k]; clash || k == "action" {
			return nil, fmt.Errorf("audit data key %q is already set by the subject", k)
		}
		data[k] = v
	}
	data["action"] = e.Action

	return &models.AuditEvent{
		ID:          models.NewID(),
		Actor:       e.Actor,
		ActorKind:   e.ActorKind,
		Kind:        e.Kind,
		Text:        e.Text,
		Source:      e.Source,
		SubjectKind: e.Subject.Kind,
		SubjectID:   e.Subject.ID,
		Namespace:   e.Subject.Namespace,
		Data:        data,
	}, nil
}

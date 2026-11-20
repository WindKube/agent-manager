package notify

import (
	"encoding/json"
	"maps"
	"time"
)

// Event is the JSON body of every delivery. ID is the audit event's id, so it
// is stable across retries and is the receiver's idempotency key.
type Event struct {
	ID         string         `json:"id"`
	Type       EventType      `json:"type"`
	OccurredAt time.Time      `json:"occurredAt"`
	Namespace  string         `json:"namespace,omitempty"`
	Subject    EventSubject   `json:"subject"`
	Actor      EventActor     `json:"actor"`
	Data       map[string]any `json:"data"`
}

type EventSubject struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type EventActor struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// NewEvent builds the payload from an audit row's columns. data.action is
// dropped: the type already says it. Audit data never carries a secret.
func NewEvent(id string, t EventType, occurredAt time.Time, namespace, subjectKind, subjectID,
	actorKind, actor string, data map[string]any) Event {
	out := make(map[string]any, len(data))
	maps.Copy(out, data)
	delete(out, "action")
	return Event{
		ID: id, Type: t, OccurredAt: occurredAt.UTC(), Namespace: namespace,
		Subject: EventSubject{Kind: subjectKind, ID: subjectID},
		Actor:   EventActor{Kind: actorKind, Name: actor},
		Data:    out,
	}
}

// Body is the exact bytes that are signed and sent.
func (e Event) Body() ([]byte, error) { return json.Marshal(e) }

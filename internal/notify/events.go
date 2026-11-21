// Package notify is the outbound webhook vocabulary shared by the api and the
// notifier role. It holds no I/O of its own.
package notify

import "slices"

// EventType is a webhook event type. Each is derived from an audit row, so an
// event exists exactly when its audit row does.
type EventType string

const (
	VersionRegistered  EventType = "package.version.registered"
	VersionStored      EventType = "package.version.stored"
	VersionFetchFailed EventType = "package.version.fetch-failed"
	VersionDeleted     EventType = "package.version.deleted"
	PackageDeleted     EventType = "package.deleted"
	ScanCompleted      EventType = "scan.completed"
	FindingAccepted    EventType = "finding.accepted"
	FindingRejected    EventType = "finding.rejected"
	WaiverExpiring     EventType = "waiver.expiring"
	WaiverExpired      EventType = "waiver.expired"
	RevisionPublished  EventType = "profile.revision.published"
	PolicyChanged      EventType = "policy.changed"
	TokenCreated       EventType = "service-token.created"
	TokenRevoked       EventType = "service-token.revoked"
	MachineForgotten   EventType = "machine.forgotten"
)

const AllEvents = "*"

// EventTypesEnum is the api's enum for an event filter entry; a test keeps it
// equal to AllEvents plus EventTypes.
const EventTypesEnum = "*,package.version.registered,package.version.stored,package.version.fetch-failed," +
	"package.version.deleted,package.deleted,scan.completed,finding.accepted,finding.rejected," +
	"waiver.expiring,waiver.expired,profile.revision.published,policy.changed," +
	"service-token.created,service-token.revoked,machine.forgotten"

type auditKey struct{ kind, action, subject string }

// fromAudit is keyed on the subject kind as well, since fetch/deleted is a
// package or a version withdrawal depending on what it is about.
var fromAudit = map[auditKey]EventType{
	{"fetch", "registered", "version"}:        VersionRegistered,
	{"fetch", "stored", "version"}:            VersionStored,
	{"fetch", "fetch-failed", "version"}:      VersionFetchFailed,
	{"fetch", "deleted", "version"}:           VersionDeleted,
	{"fetch", "deleted", "package"}:           PackageDeleted,
	{"scan", "scanned", "version"}:            ScanCompleted,
	{"approve", "accepted", "finding"}:        FindingAccepted,
	{"approve", "rejected", "finding"}:        FindingRejected,
	{"approve", "waiver-expiring", "finding"}: WaiverExpiring,
	{"approve", "waiver-expired", "finding"}:  WaiverExpired,
	{"profile", "published", "revision"}:      RevisionPublished,
	{"policy", "updated", "policy"}:           PolicyChanged,
	{"token", "created", "service-token"}:     TokenCreated,
	{"token", "revoked", "service-token"}:     TokenRevoked,
	{"sync", "forgotten", "machine"}:          MachineForgotten,
}

func EventTypes() []EventType {
	out := make([]EventType, 0, len(fromAudit))
	for _, t := range fromAudit {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// AuditKinds lets the dispatcher skip irrelevant audit kinds in SQL.
func AuditKinds() []string {
	var out []string
	for k := range fromAudit {
		if !slices.Contains(out, k.kind) {
			out = append(out, k.kind)
		}
	}
	slices.Sort(out)
	return out
}

// FromAudit maps an audit row to its event type; false means the row raises
// no event.
func FromAudit(kind, action, subjectKind string) (EventType, bool) {
	t, ok := fromAudit[auditKey{kind, action, subjectKind}]
	return t, ok
}

func (t EventType) Valid() bool {
	for _, known := range fromAudit {
		if known == t {
			return true
		}
	}
	return false
}

// Matches reports whether a subscription filter selects t in namespace. An
// empty namespace filter selects every namespace.
func Matches(eventTypes, namespaces []string, t EventType, namespace string) bool {
	if !slices.Contains(eventTypes, AllEvents) && !slices.Contains(eventTypes, string(t)) {
		return false
	}
	return len(namespaces) == 0 || slices.Contains(namespaces, namespace)
}

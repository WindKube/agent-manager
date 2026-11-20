// Package notify is the outbound webhook vocabulary shared by the api, which
// manages subscriptions, and the notifier role, which delivers: the event
// types, how an audit row maps to one, the payload, the signature and the URL
// rules. It holds no I/O of its own.
package notify

import "slices"

// EventType is a webhook event type. Every one is derived from an audit row,
// so an event exists exactly when its audit row does.
//
//	package.version.registered  fetch/registered      a version was registered and queued for fetching
//	package.version.stored      fetch/stored          a version's bytes landed (data: digest, signature)
//	package.version.fetch-failed fetch/fetch-failed   a fetch produced no bytes (data: reason)
//	package.version.deleted     fetch/deleted         a version was withdrawn from the catalog
//	package.deleted             fetch/deleted         a package was withdrawn from the catalog
//	scan.completed              scan/scanned          a scan finished (data: verdict, ruleIds, timedOut)
//	finding.accepted            approve/accepted      a finding was accepted (data: expiresAt)
//	finding.rejected            approve/rejected      a finding was rejected, quarantining its version
//	waiver.expiring             approve/waiver-expiring an accepted finding lapses within 7 days (data: expiresAt)
//	waiver.expired              approve/waiver-expired  an accepted finding lapsed (data: expiresAt)
//	profile.revision.published  profile/published     a profile revision was published
//	policy.changed              policy/updated        the organisation policy changed
//	service-token.created       token/created         a service token was created (data: scopes, expiresAt)
//	service-token.revoked       token/revoked         a service token was revoked
//	machine.forgotten           sync/forgotten        a machine was removed from the inventory
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

// AllEvents is the wildcard a subscription may filter on instead of a list.
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

// EventTypes lists every event type in a stable order.
func EventTypes() []EventType {
	out := make([]EventType, 0, len(fromAudit))
	for _, t := range fromAudit {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// AuditKinds is every audit kind some event type is derived from, so the
// dispatcher can skip the rest in SQL.
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

// Valid reports whether t is a known event type.
func (t EventType) Valid() bool {
	for _, known := range fromAudit {
		if known == t {
			return true
		}
	}
	return false
}

// Matches reports whether a subscription filter selects t in namespace. An
// empty namespace filter selects every namespace; a non-empty one never
// selects an event that has no namespace.
func Matches(eventTypes, namespaces []string, t EventType, namespace string) bool {
	if !slices.Contains(eventTypes, AllEvents) && !slices.Contains(eventTypes, string(t)) {
		return false
	}
	return len(namespaces) == 0 || slices.Contains(namespaces, namespace)
}

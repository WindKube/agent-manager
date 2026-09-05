package scanner

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"agent-manager/internal/outbox"
)

// Job is the `scan` outbox payload: the wire contract between the fetcher's
// publish transaction and this worker.
type Job struct {
	VersionID uuid.UUID `json:"versionId"`
	PackageID uuid.UUID `json:"packageId"`

	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Semver    string `json:"semver"`

	// ObjectKey is carried rather than recomputed so the scanner reads the
	// bytes that fetch committed; empty is read off the version row instead.
	ObjectKey string `json:"objectKey"`
}

// Kind is the River job kind, which is the same string as the outbox `job_kind`.
func (Job) Kind() string { return string(outbox.KindScan) }

// Validate rejects a payload this worker could not act on. It runs at
// enqueue time and at work time, since a payload read out of the queue is
// input like any other.
func (j Job) Validate() error {
	switch {
	case j.VersionID == uuid.Nil:
		return errors.New("scan job names no version")
	case j.PackageID == uuid.Nil:
		return errors.New("scan job names no package")
	case j.Namespace == "" || j.Name == "" || j.Semver == "":
		return errors.New("scan job names no publisher, name or semver")
	}
	return nil
}

// OutboxJob renders the enqueue a publish performs. SubjectVersion is
// deliberately empty: the scan idempotency key includes the rule-pack
// version, which is the scanner's own.
func (j Job) OutboxJob() (outbox.Job, error) {
	if err := j.Validate(); err != nil {
		return outbox.Job{}, err
	}
	payload, err := json.Marshal(j)
	if err != nil {
		return outbox.Job{}, fmt.Errorf("encode scan job: %w", err)
	}
	return outbox.Job{
		Kind:      outbox.KindScan,
		SubjectID: j.VersionID,
		Payload:   json.RawMessage(payload),
	}, nil
}

// String is how the job appears in a log line and an audit row.
func (j Job) String() string { return j.Namespace + "/" + j.Name + "@" + j.Semver }

// SweepJob is the `rescan-sweep` payload: one package whose already-scanned
// versions may need looking at again.
type SweepJob struct {
	PackageID uuid.UUID `json:"packageId"`
	// TriggerVersionID is excluded from the sweep: its own `scan` job is
	// already on the queue.
	TriggerVersionID uuid.UUID `json:"triggerVersionId"`
	Namespace        string    `json:"namespace"`
	Name             string    `json:"name"`
}

// Kind is the River job kind.
func (SweepJob) Kind() string { return string(outbox.KindRescanSweep) }

// Validate rejects a payload the handler could not act on.
func (s SweepJob) Validate() error {
	if s.PackageID == uuid.Nil {
		return errors.New("rescan sweep names no package")
	}
	return nil
}

// OutboxJob renders the enqueue a publish performs. The sweep itself is not
// guarded by outbox.Delivered: it fans out to per-version work that each
// carry the scan guard.
func (s SweepJob) OutboxJob() (outbox.Job, error) {
	if err := s.Validate(); err != nil {
		return outbox.Job{}, err
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return outbox.Job{}, fmt.Errorf("encode rescan sweep: %w", err)
	}
	return outbox.Job{
		Kind:      outbox.KindRescanSweep,
		SubjectID: s.PackageID,
		Payload:   json.RawMessage(payload),
	}, nil
}

// String is how the sweep appears in a log line.
func (s SweepJob) String() string {
	if s.Namespace == "" || s.Name == "" {
		return s.PackageID.String()
	}
	return s.Namespace + "/" + s.Name
}

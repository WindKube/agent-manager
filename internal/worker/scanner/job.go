package scanner

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"agent-manager/internal/outbox"
)

// Job is the `scan` outbox payload sent by the fetcher's publish transaction.
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

// Kind is the River job kind, equal to the outbox `job_kind`.
func (Job) Kind() string { return string(outbox.KindScan) }

// Validate runs at enqueue and at work time, since a queued payload is
// untrusted input too.
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

// OutboxJob leaves SubjectVersion empty: the idempotency key's rule-pack
// version is known only to the scanner.
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

// String is how the job appears in logs and audit rows.
func (j Job) String() string { return j.Namespace + "/" + j.Name + "@" + j.Semver }

// SweepJob is the `rescan-sweep` payload for one package.
type SweepJob struct {
	PackageID uuid.UUID `json:"packageId"`
	// TriggerVersionID is excluded: its own `scan` job is already queued.
	TriggerVersionID uuid.UUID `json:"triggerVersionId"`
	Namespace        string    `json:"namespace"`
	Name             string    `json:"name"`
}

// Kind is the River job kind.
func (SweepJob) Kind() string { return string(outbox.KindRescanSweep) }

// Validate rejects a payload without a package.
func (s SweepJob) Validate() error {
	if s.PackageID == uuid.Nil {
		return errors.New("rescan sweep names no package")
	}
	return nil
}

// OutboxJob builds the outbox row. The sweep is not guarded by
// outbox.Delivered because each per-version scan carries its own guard.
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

// String is how the sweep appears in logs.
func (s SweepJob) String() string {
	if s.Namespace == "" || s.Name == "" {
		return s.PackageID.String()
	}
	return s.Namespace + "/" + s.Name
}

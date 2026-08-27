package fetcher

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"agent-manager/internal/blob"
	"agent-manager/internal/fetch"
	"agent-manager/internal/outbox"
)

// Job is the `fetch` outbox payload, and therefore the wire contract between the
// api role's registration command and this worker.
//
// It lives here rather than in internal/api/commands because the consumer owns
// the shape it must be able to read: a producer-owned payload makes the worker
// import the API's command layer, which is the wrong direction for a background
// role.
type Job struct {
	// VersionID names the row this fetch fills in. The row already exists —
	// invisible, digest null — because the R5 idempotency key is
	// (job_kind, subject_id, subject_version) evaluated against the TARGET ROW, so
	// there has to be a row to evaluate against when the job is enqueued.
	VersionID uuid.UUID `json:"versionId"`
	PackageID uuid.UUID `json:"packageId"`

	Publisher string `json:"publisher"`
	Name      string `json:"name"`
	Semver    string `json:"semver"`

	Source JobSource `json:"source"`
}

// JobSource is the registration's source reference as it travels through the
// queue.
type JobSource struct {
	Kind         fetch.SourceKind `json:"kind"`
	URL          string           `json:"url,omitempty"`
	Ref          string           `json:"ref,omitempty"`
	Subdirectory string           `json:"subdirectory,omitempty"`

	ArchiveName string `json:"archiveName,omitempty"`

	// Archive carries an uploaded archive's bytes, base64 in the payload's jsonb.
	//
	// This is the only transactional door available to it: the api role holds no
	// blob.Writer — only `worker fetcher` may write bundle bytes (principle II) —
	// so an upload cannot be staged in object storage by the endpoint that receives
	// it, and a filesystem hand-off between two containers does not exist. Putting
	// the bytes in the outbox row keeps FR-001's upload path inside the one
	// transaction T042 requires: the archive cannot exist without the version row
	// that describes it, or the reverse.
	//
	// The cost is real and bounded: the 25 MB upload cap (FR-001) becomes ~33 MB of
	// base64 in the outbox row and again in the River job, both of which are pruned.
	// A dedicated staging table would halve that and needs a migration.
	Archive []byte `json:"archive,omitempty"`
}

// Kind is the River job kind, which is the same string as the outbox `job_kind`.
// One name, so a worker registers against a single value and the relay needs no
// mapping.
func (Job) Kind() string { return string(outbox.KindFetch) }

// Validate rejects a payload this worker could not act on. It runs both at
// enqueue time, so a bad registration fails the request rather than a job, and at
// work time, because a payload read out of the queue is input like any other.
func (j Job) Validate() error {
	switch {
	case j.VersionID == uuid.Nil:
		return errors.New("fetch job names no version")
	case j.PackageID == uuid.Nil:
		return errors.New("fetch job names no package")
	case j.Publisher == "" || j.Name == "" || j.Semver == "":
		return errors.New("fetch job names no publisher, name or semver")
	}
	if err := j.VersionRef().Validate(); err != nil {
		return fmt.Errorf("fetch job: %w", err)
	}

	switch j.Source.Kind {
	case fetch.SourceUpload:
		if len(j.Source.Archive) == 0 {
			return errors.New("fetch job for an upload carries no archive")
		}
	case fetch.SourceGit, fetch.SourceArchiveURL:
		if j.Source.URL == "" {
			return fmt.Errorf("fetch job of kind %s carries no url", j.Source.Kind)
		}
	default:
		return fmt.Errorf("fetch job has unknown source kind %q", j.Source.Kind)
	}
	return nil
}

// VersionRef is where this version's objects live (FR-006).
func (j Job) VersionRef() blob.VersionRef {
	return blob.VersionRef{Publisher: j.Publisher, Name: j.Name, Semver: j.Semver}
}

// OutboxJob renders the enqueue the registration command performs. The
// idempotency key it carries is (fetch, version id, semver) — the version's own
// identity, which is what `digest is not null` on that row then answers.
func (j Job) OutboxJob() (outbox.Job, error) {
	if err := j.Validate(); err != nil {
		return outbox.Job{}, err
	}
	payload, err := json.Marshal(j)
	if err != nil {
		return outbox.Job{}, fmt.Errorf("encode fetch job: %w", err)
	}
	return outbox.Job{
		Kind:           outbox.KindFetch,
		SubjectID:      j.VersionID,
		SubjectVersion: j.Semver,
		Payload:        json.RawMessage(payload),
	}, nil
}

// SourceRef is the reference handed to the fetch Source registry.
func (j Job) SourceRef() fetch.SourceRef {
	return fetch.SourceRef{
		Kind:         j.Source.Kind,
		URL:          j.Source.URL,
		Ref:          j.Source.Ref,
		Subdirectory: j.Source.Subdirectory,
		ArchiveName:  j.Source.ArchiveName,
	}
}

// String is how the job appears in a log line and an audit row.
func (j Job) String() string { return j.Publisher + "/" + j.Name + "@" + j.Semver }

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

// Job is the `fetch` outbox payload: the wire contract between the api
// role's registration command and this worker.
type Job struct {
	// VersionID names the row this fetch fills in; it already exists,
	// invisible with digest null.
	VersionID uuid.UUID `json:"versionId"`
	PackageID uuid.UUID `json:"packageId"`

	Namespace string `json:"namespace"`
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

	// Archive carries an uploaded archive's bytes, base64 in the payload's
	// jsonb: the only transactional door available, since the api role
	// holds no blob.Writer.
	Archive []byte `json:"archive,omitempty"`
}

// Kind is the River job kind, which is the same string as the outbox
// `job_kind`.
func (Job) Kind() string { return string(outbox.KindFetch) }

// Validate rejects a payload this worker could not act on. It runs both at
// enqueue time and at work time, since a payload read out of the queue is
// input like any other.
func (j Job) Validate() error {
	switch {
	case j.VersionID == uuid.Nil:
		return errors.New("fetch job names no version")
	case j.PackageID == uuid.Nil:
		return errors.New("fetch job names no package")
	case j.Namespace == "" || j.Name == "" || j.Semver == "":
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

// VersionRef is where this version's objects live.
func (j Job) VersionRef() blob.VersionRef {
	return blob.VersionRef{Namespace: j.Namespace, Name: j.Name, Semver: j.Semver}
}

// OutboxJob renders the enqueue the registration command performs.
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
func (j Job) String() string { return j.Namespace + "/" + j.Name + "@" + j.Semver }

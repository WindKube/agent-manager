package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"agent-manager/internal/worker/scanner/checks"
)

// service is the engine reached over its REST interface.
//
// The client is a plain http.Client and deliberately not internal/fetch: that
// one is the sanctioned client for URLs a USER supplied, and it refuses
// private, loopback and link-local destinations on every hop. This address is
// operator configuration naming a service inside the deployment, which is
// exactly what internal/fetch exists to refuse.
type service struct {
	opts Options
	http *http.Client
}

// New builds a client for the engine at opts.BaseURL.
func New(opts Options) (Client, error) {
	opts = opts.withDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}
	return &service{
		opts: opts,
		http: &http.Client{Timeout: opts.Timeout},
	}, nil
}

// maxResponseBytes bounds what is read back. The engine is trusted to be the
// engine, not to be bug-free.
const maxResponseBytes = 32 << 20

func (s *service) Version(ctx context.Context) (string, error) {
	var out health
	if err := s.get(ctx, "/health", &out); err != nil {
		return "", err
	}
	if !strings.EqualFold(out.Status, "healthy") {
		return "", fmt.Errorf("engine: /health reports status %q", out.Status)
	}
	if strings.TrimSpace(out.Version) == "" {
		return "", fmt.Errorf("engine: /health names no version")
	}
	return out.Version, nil
}

func (s *service) Scan(ctx context.Context, tree Tree) (Result, error) {
	zipped, err := zipTree(tree)
	if err != nil {
		return Result{}, err
	}

	body, contentType, err := s.uploadBody(zipped)
	if err != nil {
		return Result{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url("/scan-upload"), bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("engine: build the scan request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")

	var rep report
	if err := s.do(req, &rep); err != nil {
		return Result{}, err
	}
	return translate(rep, s.opts.Threshold)
}

// analyzerToggles are sent on every request. The engine already defaults each
// of these to false; they are sent explicitly so that the request this project
// makes states its own analyzer set rather than inheriting one, and so a test
// can assert it. None of them is reachable from Options: every analyzer here
// needs an API key or a network call, and the engine takes those keys as
// request HEADERS, which this client never sets.
var analyzerToggles = map[string]string{
	"use_behavioral": "true",
	"use_llm":        "false",
	"use_virustotal": "false",
	"use_aidefense":  "false",
	"use_trigger":    "false",
	"use_osv":        "false",
	"enable_meta":    "false",
}

// uploadFilename must end in .zip; the engine rejects any other name. It is
// display metadata only — the engine writes the upload under a name of its own.
const uploadFilename = "bundle.zip"

func (s *service) uploadBody(zipped []byte) (body []byte, contentType string, err error) {
	var buf bytes.Buffer
	form := multipart.NewWriter(&buf)

	part, err := form.CreateFormFile("file", uploadFilename)
	if err != nil {
		return nil, "", fmt.Errorf("engine: build the upload part: %w", err)
	}
	if _, err := part.Write(zipped); err != nil {
		return nil, "", fmt.Errorf("engine: write the upload part: %w", err)
	}

	fields := map[string]string{"policy": s.opts.Policy}
	for name, value := range analyzerToggles {
		fields[name] = value
	}
	for name, value := range fields {
		if err := form.WriteField(name, value); err != nil {
			return nil, "", fmt.Errorf("engine: write the %s field: %w", name, err)
		}
	}
	if err := form.Close(); err != nil {
		return nil, "", fmt.Errorf("engine: finish the upload body: %w", err)
	}
	return buf.Bytes(), form.FormDataContentType(), nil
}

func (s *service) url(path string) string {
	return strings.TrimSuffix(s.opts.BaseURL, "/") + path
}

func (s *service) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url(path), http.NoBody)
	if err != nil {
		return fmt.Errorf("engine: build the %s request: %w", path, err)
	}
	req.Header.Set("Accept", "application/json")
	return s.do(req, out)
}

func (s *service) do(req *http.Request, out any) error {
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("engine: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return statusError(req, resp)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("engine: read the %s response: %w", req.URL.Path, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: decode the %s response: %w", ErrShapeMismatch, req.URL.Path, err)
	}
	return nil
}

// statusError separates a package the engine declined from an engine that
// failed. The first is a blind spot on one version; the second reduces
// coverage across the catalog and must reach the caller as a failure.
func statusError(req *http.Request, resp *http.Response) error {
	detail := errorDetail(resp.Body)
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return fmt.Errorf("%w: %s: %s", ErrUnanalysable, resp.Status, detail)
	case http.StatusRequestEntityTooLarge:
		return fmt.Errorf("%w: %s: %s", ErrOverCap, resp.Status, detail)
	default:
		return fmt.Errorf("engine: %s %s: %s: %s", req.Method, req.URL.Path, resp.Status, detail)
	}
}

// errorDetail reads the engine's own message. It is the engine's text, but it
// quotes the package's file names back, so it is clipped like bundle content.
func errorDetail(body io.Reader) string {
	raw, err := io.ReadAll(io.LimitReader(body, 8<<10))
	if err != nil || len(raw) == 0 {
		return "no detail"
	}
	var payload struct {
		Detail json.RawMessage `json:"detail"`
	}
	if err := json.Unmarshal(raw, &payload); err == nil && len(payload.Detail) > 0 {
		var text string
		if err := json.Unmarshal(payload.Detail, &text); err == nil {
			return checks.Clip(text)
		}
		return checks.Clip(string(payload.Detail))
	}
	return checks.Clip(string(raw))
}

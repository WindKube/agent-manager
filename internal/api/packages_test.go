package api_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"agent-manager/internal/api"
	"agent-manager/internal/api/contract"
	"agent-manager/internal/auth"
	"agent-manager/internal/store/models"
)

// The pre-submit preview (T041) needs no database and no bucket: it extracts,
// filters, validates and derives, and writes nothing. That is the whole design —
// a preview that needed the store would be a preview that could half-register.

const conformantPluginManifest = `{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
  "name": "platform-toolkit",
  "version": "1.3.0",
  "description": "Terraform and Kubernetes review helpers.",
  "author": {"name": "Platform", "email": "platform@example.dev"},
  "keywords": ["terraform", "kubernetes"],
  "extensions": {
    "dev.agent-manager": {
      "expectedCapabilities": [
        {"name": "network", "level": "allowlisted", "detail": ["registry.example.dev"]},
        {"name": "shell", "detail": ["terraform"]}
      ]
    }
  }
}`

// scenario2Files is US1 acceptance scenario 2's archive, verbatim: a root holding
// plugin.json, skills/, mcp.json, a client namespace, .github/ and README.md.
func scenario2Files() map[string]string {
	return map[string]string{
		"plugin.json": conformantPluginManifest,
		"mcp.json": `{"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",` +
			`"mcpServers":{"terraform-state":{"type":"stdio","command":"terraform-mcp"}}}`,
		"skills/terraform-plan-review/SKILL.md":         "---\nname: terraform-plan-review\ndescription: Reviews a plan.\n---\n",
		"skills/terraform-plan-review/scripts/plan.sh":  "#!/bin/sh\nterraform plan\n",
		"skills/k8s-manifest-review/SKILL.md":           "---\nname: k8s-manifest-review\ndescription: Reviews manifests.\n---\n",
		"com.anthropic.claude-code/hooks/pre-tool.json": `{"hook":"pre-tool"}`,
		".github/workflows/ci.yml":                      "on: push\n",
		"README.md":                                     "# Platform Toolkit\n",
	}
}

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for path, body := range files {
		f, err := w.Create(path)
		require.NoError(t, err)
		_, err = f.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// upload builds a multipart body with the archive part and any form values.
func upload(t *testing.T, archive []byte, values map[string]string) (contentType string, body []byte) {
	t.Helper()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for name, value := range values {
		require.NoError(t, w.WriteField(name, value))
	}
	if archive != nil {
		part, err := w.CreateFormFile("archive", "platform-toolkit-1.3.0.zip")
		require.NoError(t, err)
		_, err = part.Write(archive)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return w.FormDataContentType(), buf.Bytes()
}

func postForm(t *testing.T, h http.Handler, path, token, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func previewHandler(t *testing.T) http.Handler {
	t.Helper()
	return handler(t, api.Deps{Sessions: resolver{principal: auth.Principal{
		Subject: "sub-kw", Email: "kw@example.com",
		Role: models.OrgRoleCatalogAdmin, Source: auth.SourceWeb,
	}}})
}

// ---------------------------------------------------------------------------
// FR-005 / US1 scenario 2 — the panel says what it dropped
// ---------------------------------------------------------------------------

func TestThePreviewListsEveryEntryWithAMarkAndNamesWhatItDropped(t *testing.T) {
	contentType, body := upload(t, zipOf(t, scenario2Files()), nil)
	rec := postForm(t, previewHandler(t), "/v1/packages/preview", "token", contentType, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var preview contract.PackagePreview
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preview))

	require.True(t, preview.Valid)
	require.Equal(t, "plugin", preview.Kind)
	require.Equal(t, "platform-toolkit", preview.Name)
	require.Equal(t, "1.3.0", preview.Version)

	// The design's panel, in order. The last row is the requirement: a dropped
	// path is REPORTED, grouped, before the user commits to registering.
	require.Equal(t, []contract.PreviewEntry{
		{Path: "plugin.json", Note: "schema valid", Kept: true, Mark: contract.MarkKept},
		{Path: "skills/", Note: "2 skills", Kept: true, Mark: contract.MarkKept},
		{Path: "mcp.json", Note: "1 server", Kept: true, Mark: contract.MarkKept},
		{Path: "com.anthropic.claude-code/hooks/", Note: "client extension", Kept: true, Mark: contract.MarkKept},
		{Path: ".github/, README.md", Note: "outside spec, dropped", Kept: false, Mark: contract.MarkDropped},
	}, preview.Entries)

	// Grouped for display, complete for the record.
	require.ElementsMatch(t, []string{".github/workflows/ci.yml", "README.md"}, preview.Dropped)

	// Components come from the FILE TREE. No manifest field enumerates them.
	require.Equal(t, []contract.PreviewComponent{
		{Kind: "skill", Name: "k8s-manifest-review", Path: "skills/k8s-manifest-review", Note: "SKILL.md"},
		{Kind: "skill", Name: "terraform-plan-review", Path: "skills/terraform-plan-review", Note: "SKILL.md + scripts/"},
		{Kind: "mcp", Name: "terraform-state", Path: "mcp.json", Note: "stdio"},
		{Kind: "ext", Name: "com.anthropic.claude-code", Path: "com.anthropic.claude-code", Note: "client extension: hooks/"},
	}, preview.Components)

	// FR-018a: the expected set is read from extensions["dev.agent-manager"] and
	// from nowhere else, and `shell` is forced to review however it was declared.
	require.Equal(t, []contract.PreviewCapability{
		{Name: "network", Level: "allowlisted", Detail: []string{"registry.example.dev"}},
		{Name: "shell", Level: "review", Detail: []string{"terraform"}},
	}, preview.Expected)

	require.Equal(t, []string{"terraform", "kubernetes"}, preview.Tags)
	require.Empty(t, preview.Problems)
}

// ---------------------------------------------------------------------------
// US1 scenario 3 — the failure is reported against the schema path
// ---------------------------------------------------------------------------

func TestANonConformantManifestIsRefusedAgainstItsSchemaPathAndNothingIsCreated(t *testing.T) {
	files := scenario2Files()
	// `publisher` is one of the fields the DESIGN MOCKUP shows and the published
	// schema does not permit; the schema's ten fields are closed by
	// additionalProperties:false. This is the R1 trap: the local copy must not be
	// relaxed to admit the mockup's vocabulary.
	files["plugin.json"] = strings.Replace(conformantPluginManifest,
		`"name": "platform-toolkit",`,
		`"name": "platform-toolkit",
  "publisher": "example",`, 1)

	contentType, body := upload(t, zipOf(t, files), nil)
	handler := previewHandler(t)

	// The preview says why, with the keyword location that refused it.
	rec := postForm(t, handler, "/v1/packages/preview", "token", contentType, body)
	require.Equal(t, http.StatusOK, rec.Code)

	var preview contract.PackagePreview
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preview))
	require.False(t, preview.Valid)
	require.NotEmpty(t, preview.Problems)
	require.Equal(t, "plugin.json", preview.Problems[0].Manifest)
	require.Equal(t, "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", preview.Problems[0].SchemaID)
	require.Contains(t, preview.Problems[0].SchemaPath, "/additionalProperties")

	// And the registration refuses BEFORE it opens a transaction, which is what
	// "no version is created and nothing is written to object storage" means. The
	// nil DB is the proof: a handler that reached the store would panic here.
	contentType, body = upload(t, zipOf(t, files), map[string]string{
		"source": "upload", "publisher": "example",
	})
	rec = postForm(t, handler, "/v1/packages", "token", contentType, body)
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())

	var problem contract.Error
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &problem))
	require.Contains(t, problem.Detail, "refused before any version was created")
	require.NotEmpty(t, problem.Errors)
	require.Contains(t, problem.Errors[0].Value, "/additionalProperties")
}

// ---------------------------------------------------------------------------
// The R3 caps, reached through the endpoint rather than asserted on the extractor
// ---------------------------------------------------------------------------

func TestThePreviewRefusesAnArchiveThatBreaksTheExtractionLimits(t *testing.T) {
	handler := previewHandler(t)

	t.Run("a member that escapes the tree is refused, not cleaned", func(t *testing.T) {
		files := scenario2Files()
		files["../../etc/passwd"] = "root:x:0:0\n"
		contentType, body := upload(t, zipOf(t, files), nil)

		rec := postForm(t, handler, "/v1/packages/preview", "token", contentType, body)
		require.Equal(t, http.StatusOK, rec.Code)

		var preview contract.PackagePreview
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preview))
		require.False(t, preview.Valid)
		require.Contains(t, preview.Problems[0].Message, "refuses")
	})

	t.Run("a tree with no manifest at its root is an ingestion failure", func(t *testing.T) {
		contentType, body := upload(t, zipOf(t, map[string]string{"README.md": "# nothing here\n"}), nil)

		rec := postForm(t, handler, "/v1/packages/preview", "token", contentType, body)
		require.Equal(t, http.StatusOK, rec.Code)

		var preview contract.PackagePreview
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preview))
		require.False(t, preview.Valid)
		require.NotEmpty(t, preview.Problems)
	})

	t.Run("no archive at all", func(t *testing.T) {
		contentType, body := upload(t, nil, nil)
		rec := postForm(t, handler, "/v1/packages/preview", "token", contentType, body)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	})
}

// ---------------------------------------------------------------------------
// Who may register, and what a registration must carry
// ---------------------------------------------------------------------------

func TestRegistrationRefusesWhatItCannotResolveBeforeTouchingTheDatabase(t *testing.T) {
	// Every case below must be refused by the handler, so the nil DB never gets
	// dereferenced. A handler that opened a transaction first would panic.
	handler := previewHandler(t)

	for _, tc := range []struct {
		name   string
		values map[string]string
		status int
		detail string
	}{
		{
			name:   "neither an archive nor a url",
			values: map[string]string{"publisher": "example"},
			status: http.StatusUnprocessableEntity,
			detail: "needs either an archive or a url",
		},
		{
			name:   "an archive attached to a git registration",
			values: map[string]string{"source": "git", "url": "https://github.com/org/plugin", "publisher": "example"},
			status: http.StatusUnprocessableEntity,
			detail: "carries no archive",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var archive []byte
			if strings.Contains(tc.detail, "carries no archive") {
				archive = zipOf(t, scenario2Files())
			}
			contentType, body := upload(t, archive, tc.values)
			rec := postForm(t, handler, "/v1/packages", "token", contentType, body)
			require.Equal(t, tc.status, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), tc.detail)
		})
	}
}

func TestAReadOnlyIdentityCannotRegisterAPackage(t *testing.T) {
	// The grant cannot express this: am_api holds it on behalf of every caller and
	// the database cannot tell them apart.
	readOnly := handler(t, api.Deps{Sessions: resolver{principal: auth.Principal{
		Subject: "sub-ro", Role: models.OrgRoleReadOnly, Source: auth.SourceWeb,
	}}})

	contentType, body := upload(t, zipOf(t, scenario2Files()), map[string]string{
		"source": "upload", "publisher": "example",
	})
	rec := postForm(t, readOnly, "/v1/packages", "token", contentType, body)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	// The negative control: the same request from an identity with a role that is
	// allowed gets past the check and fails later, on the database it was never
	// given here.
	require.NotEqual(t, http.StatusForbidden,
		postForm(t, previewHandler(t), "/v1/packages", "token", contentType, body).Code)
}

func TestBothRegistrationOperationsRequireAToken(t *testing.T) {
	handler := previewHandler(t)
	contentType, body := upload(t, zipOf(t, scenario2Files()), nil)

	for _, path := range []string{"/v1/packages/preview", "/v1/packages"} {
		rec := postForm(t, handler, path, "", contentType, body)
		require.Equal(t, http.StatusUnauthorized, rec.Code, path)
	}
}

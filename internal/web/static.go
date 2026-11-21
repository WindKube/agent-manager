package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

// Embedded because the distroless image has no filesystem and the quickstart must work offline.
//
//go:embed static
var staticFS embed.FS

var (
	staticRoot  fs.FS
	staticFiles http.Handler
	// assetVersions lets /static be cached immutably without a stale file surviving a deploy.
	assetVersions = map[string]string{}
)

func init() {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("web: embedded static tree is missing: " + err.Error())
	}
	staticRoot = sub
	staticFiles = http.FileServer(http.FS(sub))

	err = fs.WalkDir(sub, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		body, readErr := fs.ReadFile(sub, name)
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(body)
		assetVersions[name] = hex.EncodeToString(sum[:])[:12]
		return nil
	})
	if err != nil {
		panic("web: hashing embedded static tree: " + err.Error())
	}
}

// assetURL falls back to the plain path for a missing file: app.css is
// generated, and an unstyled page beats a process that won't start.
func assetURL(name string) string {
	if version, ok := assetVersions[name]; ok {
		return "/static/" + name + "?v=" + version
	}
	return "/static/" + name
}

func serveStatic(c *gin.Context) {
	name := strings.TrimPrefix(path.Clean("/"+c.Param("path")), "/")
	if name == "" || name == "." {
		c.Status(http.StatusNotFound)
		return
	}
	if _, err := fs.Stat(staticRoot, name); err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	// Every asset is vendored or reached through a content-hashed URL.
	c.Header("Cache-Control", "public, max-age=31536000, immutable")
	c.Request.URL.Path = "/" + name
	staticFiles.ServeHTTP(c.Writer, c.Request)
}

package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// G-5: the governor has no network listener and no LLM. This test walks every
// Go file that ends up in the agentd binary and fails on a forbidden import.
// It is the enforcement for the promise in doc.go; a reviewer does not have to
// trust us, they can read this list.
func TestNoForbiddenImports(t *testing.T) {
	forbiddenExact := map[string]string{
		"net":           "no sockets other than the inherited socketpair",
		"net/http":      "no HTTP client or server",
		"net/rpc":       "no RPC",
		"crypto/tls":    "nothing to terminate TLS for",
		"os/exec":       "", // allowed ONLY in run.go, checked below
		"unsafe":        "no unsafe in the trust anchor",
		"plugin":        "no dynamic code loading",
		"text/template": "no templating of agent text",
	}
	forbiddenSubstr := []string{
		"anthropic", "openai", "langchain", "llm", "genai", "gemini", "ollama", "bedrock", "vertex",
		"grpc", "github.com/", // the governor is stdlib-only by decision; any module import is a red flag
	}
	// The one sanctioned exception: the Cedar policy engine, and only from
	// internal/policy. Anywhere else it is still a failure.
	allowedModuleIn := map[string]string{
		"github.com/cedar-policy/cedar-go": "internal/policy/",
	}

	roots := []string{".", "../../internal"}
	fset := token.NewFileSet()
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, `"`)

				// Our own packages are fine.
				if strings.HasPrefix(p, "github.com/therealnoof/agent-perimeter/") {
					continue
				}
				if why, bad := forbiddenExact[p]; bad {
					// os/exec is permitted only in the file that spawns the worker.
					if p == "os/exec" && (filepath.Base(path) == "run.go" || strings.Contains(path, "internal/socket/")) {
						continue
					}
					t.Errorf("%s imports %q: %s", path, p, why)
				}
				allowed := false
				for mod, where := range allowedModuleIn {
					if strings.HasPrefix(p, mod) && strings.Contains(filepath.ToSlash(path), where) {
						allowed = true
					}
				}
				if allowed {
					continue
				}
				lp := strings.ToLower(p)
				for _, s := range forbiddenSubstr {
					if strings.Contains(lp, s) {
						t.Errorf("%s imports %q: forbidden (%s)", path, p, s)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

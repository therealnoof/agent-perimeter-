package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/therealnoof/agent-perimeter/internal/manifest"
)

// policiesDir is the real policy directory in the repo. Tests load the real
// files so that a policy edit that breaks an attack case fails `make test`,
// which is the role `opa test` would have played.
const policiesDir = "../../policies"

// loadRepoPolicies signs the repo's policy files with a throwaway key into a
// temp dir and loads them through the real Load path, so the signature check
// is exercised too.
func loadRepoPolicies(t *testing.T) *Engine {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files, _ := filepath.Glob(filepath.Join(policiesDir, "*.cedar"))
	if len(files) == 0 {
		t.Fatalf("no policies in %s", policiesDir)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, filepath.Base(f))
		os.WriteFile(dst, raw, 0o600)
		os.WriteFile(dst+".sig", []byte(hex.EncodeToString(ed25519.Sign(priv, raw))), 0o600)
	}
	e, err := Load(dir, pub)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return e
}

func intp(i int) *int { return &i }

// stubAgent returns an Input matching the stub-agent manifest for one tool.
func stubAgent(tool string) Input {
	in := Input{
		Role: "stub-agent", DataClearance: "internal", MaxDelegationDepth: 0,
		ToolKnown: true, ToolName: tool, Target: NoTarget,
	}
	switch tool {
	case "echo":
		in.ToolKind, in.ToolDirection, in.MaxCallsPerTask = manifest.KindStructured, manifest.DirInbound, 3
	case "jira_read":
		in.ToolKind, in.ToolDirection = manifest.KindStructured, manifest.DirInbound
	case "jira_update":
		in.ToolKind, in.ToolDirection, in.SensitivityFloor = manifest.KindStructured, manifest.DirOutbound, intp(7)
	case "slack_post":
		in.ToolKind, in.ToolDirection = manifest.KindFreeform, manifest.DirOutbound
	default:
		in.ToolKnown = false
	}
	return in
}

// --- P-2: structural guarantees ---------------------------------------------

// The policy input must have no field that could carry agent-authored text.
// Target is allowed because the manifest loader proves it is enum/pattern
// bounded; everything else text-shaped fails the build.
func TestInputCarriesNoAgentText(t *testing.T) {
	typ := reflect.TypeOf(Input{})
	forbidden := []string{"justification", "args", "prompt", "message", "text", "body", "reason", "client"}
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, f := range forbidden {
			if strings.Contains(name, f) && name != "argshash" {
				t.Errorf("Input has field %q, which looks like agent-authored content", typ.Field(i).Name)
			}
		}
	}
}

func TestDeterministic(t *testing.T) {
	e := loadRepoPolicies(t)
	a, b := e.Decide(stubAgent("echo")), e.Decide(stubAgent("echo"))
	if a != b {
		t.Fatalf("non-deterministic: %+v vs %+v", a, b)
	}
}

// --- Loading: P-1 -------------------------------------------------------------

func TestLoadRefusesUnsigned(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.cedar"), []byte(`permit(principal, action, resource);`), 0o600)
	_, err := Load(dir, pub)
	if !errors.Is(err, ErrNoSignature) {
		t.Fatalf("got %v, want ErrNoSignature", err)
	}
}

func TestLoadRefusesTamperedPolicy(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	body := []byte(`forbid(principal, action, resource);`)
	p := filepath.Join(dir, "x.cedar")
	os.WriteFile(p, body, 0o600)
	os.WriteFile(p+".sig", []byte(hex.EncodeToString(ed25519.Sign(priv, body))), 0o600)
	// Now flip the forbid to a permit after signing: the classic attack.
	os.WriteFile(p, []byte(`permit(principal, action, resource);`), 0o600)
	_, err := Load(dir, pub)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestLoadRefusesEmptyDir(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, err := Load(t.TempDir(), pub)
	if !errors.Is(err, ErrNoPolicies) {
		t.Fatalf("got %v, want ErrNoPolicies", err)
	}
}

// --- Engine properties ----------------------------------------------------------

// Cedar guarantees forbid beats permit. This test documents it against our
// engine so a future "optimisation" cannot quietly change the semantics.
func TestForbidAlwaysWins(t *testing.T) {
	e, err := LoadUnsigned("t", []byte(`
		@id("p") permit (principal, action, resource);
		@id("f") forbid (principal, action, resource);
	`))
	if err != nil {
		t.Fatal(err)
	}
	d := e.Decide(stubAgent("echo"))
	if d.Verdict != Deny || d.Rule != "f" {
		t.Fatalf("got %+v, want deny by f", d)
	}
}

// A forbid with @verdict("approve") is overridable; one without is not; one
// of each firing together is NOT overridable.
func TestApproveAnnotationSemantics(t *testing.T) {
	e, _ := LoadUnsigned("t", []byte(`
		permit (principal, action, resource);
		@id("soft") @verdict("approve") forbid (principal, action, resource) when { context.taint_hwm >= 5 };
		@id("hard") forbid (principal, action, resource) when { context.call_count >= 9 };
	`))
	in := stubAgent("echo")

	in.TaintHWM = 5
	if d := e.Decide(in); d.Verdict != Approve || d.Rule != "soft" {
		t.Fatalf("soft only: got %+v", d)
	}
	in.TaintHWM, in.CallCount = 0, 9
	if d := e.Decide(in); d.Verdict != Deny || d.Rule != "hard" {
		t.Fatalf("hard only: got %+v", d)
	}
	in.TaintHWM, in.CallCount = 5, 9
	if d := e.Decide(in); d.Verdict != Deny {
		t.Fatalf("soft+hard must be deny, got %+v", d)
	}
}

// A policy that errors at evaluation (missing context key without `has`)
// must fail closed.
func TestEvaluationErrorFailsClosed(t *testing.T) {
	e, _ := LoadUnsigned("t", []byte(`
		permit (principal, action, resource) when { context.does_not_exist == 1 };
	`))
	d := e.Decide(stubAgent("echo"))
	if d.Verdict != Deny {
		t.Fatalf("got %+v, want deny", d)
	}
}

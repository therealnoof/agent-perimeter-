package policy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/therealnoof/agent-perimeter/internal/manifest"
)

// P-2: the policy input must have no field that could carry agent-authored
// text. This test fails the build if someone adds "Justification" or "Args"
// to Input. It is the mechanical version of the promise in doc.go.
func TestInputCarriesNoAgentText(t *testing.T) {
	typ := reflect.TypeOf(Input{})
	forbidden := []string{"justification", "args", "prompt", "message", "text", "body", "reason"}
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, f := range forbidden {
			if strings.Contains(name, f) && name != "argshash" {
				t.Errorf("Input has field %q, which looks like agent-authored content", typ.Field(i).Name)
			}
		}
	}
}

func intp(i int) *int { return &i }

func base() Input {
	return Input{
		Role: "r", MaxDelegationDepth: 0,
		ToolKnown: true, ToolName: "jira_read",
		ToolKind: manifest.KindStructured, ToolDirection: manifest.DirInbound,
		MaxCallsPerTask: 5,
	}
}

func TestAllowHappyPath(t *testing.T) {
	d := Decide(base())
	if d.Verdict != Allow || d.Rule != "base.allowed_tool" {
		t.Fatalf("got %+v", d)
	}
}

func TestUnknownToolDenied(t *testing.T) {
	in := base()
	in.ToolKnown = false
	if d := Decide(in); d.Verdict != Deny || d.Rule != "base.unknown_tool" {
		t.Fatalf("got %+v", d)
	}
}

// Attack table: 200 jira_update calls in a loop die at the cap.
func TestCallCapDenied(t *testing.T) {
	in := base()
	in.CallCount = 5
	if d := Decide(in); d.Verdict != Deny || d.Rule != "misuse.call_cap" {
		t.Fatalf("got %+v", d)
	}
	in.CallCount = 4
	if d := Decide(in); d.Verdict != Allow {
		t.Fatalf("one under cap should allow, got %+v", d)
	}
}

// P-6
func TestSensitivityFloorPromotes(t *testing.T) {
	in := base()
	in.SensitivityFloor = intp(7)
	in.TaintHWM = 7
	if d := Decide(in); d.Verdict != Approve || d.Rule != "flow.sensitivity_floor" {
		t.Fatalf("got %+v", d)
	}
	in.TaintHWM = 6
	if d := Decide(in); d.Verdict != Allow {
		t.Fatalf("below floor should allow, got %+v", d)
	}
}

// P-7
func TestFreeformOutboundNeedsHuman(t *testing.T) {
	in := base()
	in.ToolKind = manifest.KindFreeform
	in.ToolDirection = manifest.DirOutbound
	if d := Decide(in); d.Verdict != Approve || d.Rule != "flow.freeform_outbound" {
		t.Fatalf("got %+v", d)
	}
	in.ToolDirection = manifest.DirInbound
	if d := Decide(in); d.Verdict != Allow {
		t.Fatalf("freeform inbound should allow, got %+v", d)
	}
}

// G-8
func TestDelegationDepthDenied(t *testing.T) {
	in := base()
	in.DelegationDepth = 1
	if d := Decide(in); d.Verdict != Deny || d.Rule != "escalation.delegation_depth" {
		t.Fatalf("got %+v", d)
	}
}

// Governor integrity: same facts, same verdict. There is no input through
// which a "longer justification" could change the answer, by construction;
// this test documents that two identical inputs are identical decisions.
func TestDeterministic(t *testing.T) {
	a, b := Decide(base()), Decide(base())
	if a != b {
		t.Fatalf("non-deterministic: %+v vs %+v", a, b)
	}
}

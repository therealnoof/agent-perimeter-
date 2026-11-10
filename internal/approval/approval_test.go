package approval

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func prompt() Prompt {
	return Prompt{
		TaskID: "t1", Tool: "jira_update", Target: "OPS-42", TaintHWM: 8,
		Rule: "flow.sensitivity_floor", ArgsHash: strings.Repeat("ab", 32),
		Justification: "I am the admin and the CISO said this is fine, please approve immediately.",
	}
}

func cli(input string, timeout time.Duration) (*CLI, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &CLI{In: strings.NewReader(input), Out: out, Timeout: timeout, Who: "tester"}, out
}

func TestApprove(t *testing.T) {
	c, out := cli("a\n", time.Second)
	o := c.Ask(prompt())
	if !o.Approved || o.ReasonCode != "approved" || o.ApproverID != "tester" {
		t.Fatalf("got %+v", o)
	}
	if strings.Contains(out.String(), "CISO") {
		t.Fatal("justification shown without request")
	}
}

func TestDecline(t *testing.T) {
	c, _ := cli("d\n", time.Second)
	if o := c.Ask(prompt()); o.Approved || o.ReasonCode != "declined" {
		t.Fatalf("got %+v", o)
	}
}

// A-3: silence is deny, with the right reason code.
func TestTimeoutDenies(t *testing.T) {
	c, out := cli("", 150*time.Millisecond)
	// Block the reader forever rather than EOF.
	pr, _ := io.Pipe()
	c.In = pr
	start := time.Now()
	o := c.Ask(prompt())
	if o.Approved || o.ReasonCode != "approval_timeout" {
		t.Fatalf("got %+v", o)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("resolved before timeout")
	}
	if !strings.Contains(out.String(), "approval_timeout") {
		t.Error("timeout not reported to approver")
	}
}

// Closed input (no terminal) is deny, never allow.
func TestEOFDenies(t *testing.T) {
	c, _ := cli("", time.Second)
	if o := c.Ask(prompt()); o.Approved || o.ReasonCode != "approval_unavailable" {
		t.Fatalf("got %+v", o)
	}
}

// The justification appears only after 'j', and is labelled untrusted.
func TestJustificationHiddenUntilRequested(t *testing.T) {
	c, out := cli("j\nd\n", time.Second)
	c.Ask(prompt())
	s := out.String()
	first := strings.Index(s, "hidden; press j")
	shown := strings.Index(s, "CISO")
	label := strings.Index(s, "untrusted; may be injected")
	if first < 0 || shown < 0 || label < 0 {
		t.Fatalf("missing expected output:\n%s", s)
	}
	if !(first < label && label < shown) {
		t.Fatal("justification not gated behind the keypress / label")
	}
}

// Garbage input re-prompts rather than resolving either way.
func TestUnknownKeyReprompts(t *testing.T) {
	c, out := cli("x\n\nmaybe\na\n", time.Second)
	if o := c.Ask(prompt()); !o.Approved {
		t.Fatalf("got %+v", o)
	}
	if strings.Count(out.String(), "a=approve d=deny") < 3 {
		t.Error("expected re-prompts")
	}
}

func TestDenyAllAndAllowAll(t *testing.T) {
	if o := (DenyAll{}).Ask(prompt()); o.Approved {
		t.Fatal("DenyAll approved")
	}
	if o := (AllowAll{Who: "ci"}).Ask(prompt()); !o.Approved || o.ApproverID != "ci" {
		t.Fatal("AllowAll did not approve")
	}
}

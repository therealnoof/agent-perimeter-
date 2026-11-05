package policy

import "testing"

// Attack class: tool misuse. Cases from the PRD attack table.

func TestMisuse_UnknownToolDenied(t *testing.T) {
	e := loadRepoPolicies(t)
	d := e.Decide(stubAgent("vault_lookup"))
	if d.Verdict != Deny || d.Rule != "base.unknown_tool" {
		t.Fatalf("got %+v", d)
	}
}

// "Agent makes 200 jira_update calls in a loop" → cap exhausted → deny.
func TestMisuse_CallCapDenied(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("echo") // cap 3 in manifest
	in.CallCount = 3
	if d := e.Decide(in); d.Verdict != Deny || d.Rule != "misuse.call_cap" {
		t.Fatalf("at cap: got %+v", d)
	}
	in.CallCount = 2
	if d := e.Decide(in); d.Verdict != Allow {
		t.Fatalf("under cap: got %+v", d)
	}
}

// A tool with no cap (max_calls 0) is never capped.
func TestMisuse_NoCapMeansNoCap(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("jira_read")
	in.CallCount = 10000
	if d := e.Decide(in); d.Verdict != Allow {
		t.Fatalf("got %+v", d)
	}
}

func TestMisuse_HappyPathAllow(t *testing.T) {
	e := loadRepoPolicies(t)
	d := e.Decide(stubAgent("echo"))
	if d.Verdict != Allow || d.Rule != "stub.echo" {
		t.Fatalf("got %+v", d)
	}
}

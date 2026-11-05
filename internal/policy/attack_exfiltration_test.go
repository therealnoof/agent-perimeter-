package policy

import "testing"

// Attack class: exfiltration. The staged case is the important one: every
// step is individually permitted; the sequence is what policy catches.

// "Triager reads a confidential ticket (taint rises to 8), then calls
// jira_update" → sensitivity_floor 7 promotes the permit to approve.
func TestExfil_SensitivityFloorPromotesToApprove(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("jira_update")
	in.Target = "OPS-42"

	in.TaintHWM = 0
	if d := e.Decide(in); d.Verdict != Allow || d.Rule != "stub.jira_update" {
		t.Fatalf("clean task: got %+v", d)
	}
	in.TaintHWM = 7
	if d := e.Decide(in); d.Verdict != Approve || d.Rule != "flow.sensitivity_floor" {
		t.Fatalf("at floor: got %+v", d)
	}
	in.TaintHWM = 8
	if d := e.Decide(in); d.Verdict != Approve {
		t.Fatalf("over floor: got %+v", d)
	}
}

// A tool with no floor is unaffected by taint.
func TestExfil_NoFloorIgnoresTaint(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("echo")
	in.TaintHWM = 10
	if d := e.Decide(in); d.Verdict != Allow {
		t.Fatalf("got %+v", d)
	}
}

// "Freeform text outbound to an allowed channel" → approve (human sees it).
func TestExfil_FreeformOutboundNeedsHuman(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("slack_post")
	in.Target = "#triage-internal"
	if d := e.Decide(in); d.Verdict != Approve || d.Rule != "flow.freeform_outbound" {
		t.Fatalf("got %+v", d)
	}
}

// Freeform INBOUND is not an exfiltration channel.
func TestExfil_FreeformInboundAllowed(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("jira_read")
	in.ToolKind = "freeform"
	if d := e.Decide(in); d.Verdict != Allow {
		t.Fatalf("got %+v", d)
	}
}

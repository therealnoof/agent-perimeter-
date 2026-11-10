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

// D-4 egress: a credential shape in an outbound call is a hard deny; a
// generic shape is a human decision; a governor-issued value is a hard deny
// even on a fully permitted call.
func TestExfil_EgressScanLevels(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("jira_update")
	in.Target = "OPS-1"
	in.EgressHit = "high"
	if d := e.Decide(in); d.Verdict != Deny || d.Rule != "egress.high_confidence" {
		t.Fatalf("high: got %+v", d)
	}
	in.EgressHit = "active"
	if d := e.Decide(in); d.Verdict != Deny || d.Rule != "egress.active" {
		t.Fatalf("active: got %+v", d)
	}
	in.EgressHit = "low"
	if d := e.Decide(in); d.Verdict != Approve || d.Rule != "egress.low_confidence" {
		t.Fatalf("low: got %+v", d)
	}
	in.EgressHit = "none"
	if d := e.Decide(in); d.Verdict != Allow {
		t.Fatalf("none: got %+v", d)
	}
}

// A high hit beats an overridable floor: when both fire, nobody can approve.
func TestExfil_HighHitNotOverridableEvenWithFloor(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("jira_update")
	in.Target, in.TaintHWM, in.EgressHit = "OPS-1", 9, "high"
	if d := e.Decide(in); d.Verdict != Deny {
		t.Fatalf("got %+v", d)
	}
}

// D-4 ingress: detokenize is permitted for the role but always a human call.
func TestExfil_DetokenizeAlwaysNeedsHuman(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("jira_read") // borrow structured/inbound shape
	in.ToolName, in.Target = "detokenize", "tok_9f2a7c1e"
	if d := e.Decide(in); d.Verdict != Approve || d.Rule != "flow.detokenize" {
		t.Fatalf("got %+v", d)
	}
}

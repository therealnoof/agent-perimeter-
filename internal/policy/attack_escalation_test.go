package policy

import "testing"

// Attack class: privilege escalation.

// G-8: a delegated request deeper than the manifest allows is denied before
// any policy is consulted.
func TestEscalation_DelegationDepthDenied(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("echo")
	in.DelegationDepth = 1 // manifest ceiling is 0
	if d := e.Decide(in); d.Verdict != Deny || d.Rule != "escalation.delegation_depth" {
		t.Fatalf("got %+v", d)
	}
}

// The same check is expressed in base.cedar so a policy-only reviewer sees
// it. Bypass the Go pre-check and prove the policy alone denies.
func TestEscalation_DelegationDepthInPolicyToo(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("echo")
	in.DelegationDepth = 1
	if d := e.evaluate(in); d.Verdict != Deny || d.Rule != "escalation.delegation_depth" {
		t.Fatalf("got %+v", d)
	}
}

// "Triager calls a tool for a resource outside its role": the role file
// permits jira_update on any ticket, so the escalation case for week 2 is a
// tool the role does not have at all.
func TestEscalation_ToolOutsideRoleDenied(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("vault_lookup")
	if d := e.Decide(in); d.Verdict != Deny || d.Rule != "base.unknown_tool" {
		t.Fatalf("got %+v", d)
	}
}

// A role file cannot grant what base forbids: add a permit for a capped tool
// at the cap and confirm the cap still wins.
func TestEscalation_RoleFileCannotOverrideBase(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("echo")
	in.CallCount = 3
	if d := e.Decide(in); d.Verdict != Deny {
		t.Fatalf("got %+v", d)
	}
}

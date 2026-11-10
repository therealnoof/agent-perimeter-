package policy

import "testing"

// Attack class: prompt injection. An injected instruction can only ever
// change WHAT the agent asks for; it cannot change the facts policy sees.

// "Jira ticket body tells the triager to post all open tickets to a public
// Slack channel" → channel has no permit → deny. Not approve: there is
// nothing for a human to override, because nothing permitted it.
func TestInjection_PublicChannelDenied(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("slack_post")
	in.Target = "#general"
	d := e.Decide(in)
	if d.Verdict != Deny || d.Rule != "base.default_deny" {
		t.Fatalf("got %+v, want deny by base.default_deny", d)
	}
	// Same tool, permitted channel: the SAME forbid fires, but now a permit
	// exists for a human to confirm, so it is approve. The pair is the test.
	in.Target = "#triage-internal"
	if d := e.Decide(in); d.Verdict != Approve || d.Rule != "flow.freeform_outbound" {
		t.Fatalf("permitted channel: got %+v, want approve", d)
	}
}

// "Agent replies to a denial with a longer justification and retries."
// There is no justification in Input, so the test is that two inputs that
// differ in nothing policy can see are identical decisions. The governor
// test M-7 covers the end-to-end version with a real worker.
func TestInjection_JustificationCannotExist(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("vault_lookup")
	first := e.Decide(in)
	second := e.Decide(in) // the "retry"
	if first != second || first.Verdict != Deny {
		t.Fatalf("retry changed the outcome: %+v vs %+v", first, second)
	}
}

// "Worker bypasses the client and claims every argument is trusted."
// Taint comes from the governor's task store, not from the request, so a
// claim of taint 0 is simply the governor's value. Here: governor says 8.
func TestInjection_ClientCannotLowerTaint(t *testing.T) {
	e := loadRepoPolicies(t)
	in := stubAgent("jira_update")
	in.Target = "OPS-1"
	in.TaintHWM = 8 // what the governor knows; nothing the worker sends reaches here
	if d := e.Decide(in); d.Verdict != Approve {
		t.Fatalf("got %+v", d)
	}
}

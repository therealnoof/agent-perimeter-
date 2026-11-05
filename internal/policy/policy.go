package policy

import "github.com/therealnoof/agent-perimeter/internal/manifest"

// Verdict is one of three outcomes. There is no fourth.
type Verdict string

const (
	Allow   Verdict = "allow"
	Deny    Verdict = "deny"
	Approve Verdict = "approve" // route to a human; the governor decides what that means
)

// Input is every fact policy may consider. It is built by the governor, not
// parsed from the request. Compare it with schema.Request: Tool and TaskID
// come through, Args is reduced to a hash, Justification does not exist here.
type Input struct {
	// From the manifest.
	Role               string
	MaxDelegationDepth int

	// About the tool being requested. ToolKnown is false when the manifest has
	// no such tool; the other Tool* fields are then zero.
	ToolKnown        bool
	ToolName         string
	ToolKind         manifest.Kind
	ToolDirection    manifest.Direction
	SensitivityFloor *int
	MaxCallsPerTask  int

	// From the task store (G-7).
	CallCount       int // allowed calls of this tool so far in this task
	TaintHWM        int
	DelegationDepth int

	// About the request. ArgsHash is the hex SHA-256 of the canonical args.
	ArgsHash string
}

// Decision is the verdict plus which rule produced it, for the audit record.
type Decision struct {
	Verdict    Verdict
	Rule       string // short stable identifier, e.g. "base.unknown_tool"
	ReasonCode string // for the structured refusal sent to the worker (A-4)
}

// Decide is the week-1 policy. It is intentionally short and reads top to
// bottom as a list of rules; week 2 moves these same rules into Rego so that
// `opa test` can cover them per attack class.
//
// Rules only ever make the outcome stricter as you read down. The first rule
// that fires wins.
func Decide(in Input) Decision {
	// G-8: delegation depth is checked before anything else.
	if in.DelegationDepth > in.MaxDelegationDepth {
		return Decision{Deny, "escalation.delegation_depth", "delegation_depth_exceeded"}
	}

	// base: the role must actually have this tool.
	if !in.ToolKnown {
		return Decision{Deny, "base.unknown_tool", "tool_not_in_manifest"}
	}

	// misuse: per-task call cap, enforced here and not in any token (C-3).
	if in.MaxCallsPerTask > 0 && in.CallCount >= in.MaxCallsPerTask {
		return Decision{Deny, "misuse.call_cap", "call_cap_exceeded"}
	}

	// P-6: sensitivity floor promotes allow to approve.
	if in.SensitivityFloor != nil && in.TaintHWM >= *in.SensitivityFloor {
		return Decision{Approve, "flow.sensitivity_floor", "sensitivity_floor"}
	}

	// P-7: freeform text leaving the perimeter needs a human unless a later
	// rule (week 2, per-role explicit allow) says otherwise.
	if in.ToolKind == manifest.KindFreeform && in.ToolDirection == manifest.DirOutbound {
		return Decision{Approve, "flow.freeform_outbound", "freeform_outbound"}
	}

	return Decision{Allow, "base.allowed_tool", ""}
}

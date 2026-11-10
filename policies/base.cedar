// base.cedar: rules that apply to every role, every tool.
//
// Reading guide for people new to Cedar:
//   permit (...) when {...}  grants, if nothing forbids.
//   forbid (...) when {...}  blocks. A forbid always beats a permit.
//   @id("...")               the rule name written to the audit chain.
//   @verdict("approve")      on a forbid: a human may override this one.
//                            A forbid without it can never be overridden.
//
// principal = Agent::"<role>"         from the signed manifest
// action    = Action::"<tool name>"
// resource  = Target::"<resource_arg value>" or Target::"-"
// context   = facts the governor computed: kind, direction, call_count,
//             max_calls, taint_hwm, sensitivity_floor (if set),
//             delegation_depth, max_delegation_depth
//
// This file contains only forbids. Permits live in the per-role files so a
// reviewer can see every grant for a role in one place. Because forbids win,
// nothing in a role file can loosen anything written here.

// G-8 / escalation: a task deeper than its manifest allows is denied.
// (Also enforced in Go before policy runs; restated here so a policy-only
// reviewer sees the ceiling.)
@id("escalation.delegation_depth")
forbid (principal, action, resource)
when { context.delegation_depth > context.max_delegation_depth };

// C-3 / misuse: per-task call cap. max_calls of 0 means no cap.
@id("misuse.call_cap")
forbid (principal, action, resource)
when { context.max_calls > 0 && context.call_count >= context.max_calls };

// P-6 / exfiltration: once the task has touched data at or above the tool's
// sensitivity floor, this tool needs a human. Overridable: that is the point.
@id("flow.sensitivity_floor")
@verdict("approve")
forbid (principal, action, resource)
when { context has sensitivity_floor && context.taint_hwm >= context.sensitivity_floor };

// P-7 / exfiltration: arbitrary text leaving the perimeter needs a human.
// Overridable. Note the division of labour: this rule says freeform outbound
// text is never silently allowed; the role file says WHICH targets are
// permitted at all. A target with no permit is denied outright, a permitted
// target reaches a human.
@id("flow.freeform_outbound")
@verdict("approve")
forbid (principal, action, resource)
when { context.kind == "freeform" && context.direction == "outbound" };

// D-4 / exfiltration: the governor scans the arguments of every OUTBOUND
// tool for things that must not leave. Three levels:
//   active  a value the governor itself issued (a redaction placeholder,
//           one of its token ids) — certain, never overridable
//   high    a distinctive credential shape (AWS key, GitHub token, PEM
//           private key, bearer in a URL) — never overridable
//   low     a generic secret-looking shape — a human decides
@id("egress.active")
forbid (principal, action, resource)
when { context.egress_hit == "active" };

@id("egress.high_confidence")
forbid (principal, action, resource)
when { context.egress_hit == "high" };

@id("egress.low_confidence")
@verdict("approve")
forbid (principal, action, resource)
when { context.egress_hit == "low" };

// D-4 / ingress: reading back a value the governor redacted is itself a
// tool call, and it always goes to a human. A role file may permit the
// detokenize tool; it can never make it silent.
@id("flow.detokenize")
@verdict("approve")
forbid (principal, action == Action::"detokenize", resource);

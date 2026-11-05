// Package policy turns structural facts about a request into a verdict by
// evaluating signed Cedar policies. Requirements P-1, P-2, P-3, P-6, P-7, G-8.
//
// Why Cedar: it is an authorization language, not a general one. Policies
// cannot loop, cannot recurse, always terminate, and a `forbid` always beats a
// `permit`. That last property is the one this package most depends on: a
// later policy can only make an outcome stricter, never looser, and that is a
// guarantee of the language rather than a convention we test for.
//
// How the three verdicts come out of a two-verdict language:
//
//   - Cedar says allow  → Allow.
//   - Cedar says deny, and every forbid that fired carries the annotation
//     @verdict("approve")  → Approve: a human may override.
//   - Cedar says deny, and any forbid that fired has no such annotation, or
//     no permit matched at all  → Deny: nobody may override.
//
// The rule name recorded in the audit chain comes from an @id("…") annotation
// on the policy that fired, so an operator reading the log sees
// "flow.sensitivity_floor", not "policy3".
//
// The single most important property of this package is what Input does NOT
// contain: the agent's justification string, the raw args, or any other free
// text the agent wrote. Input is built by the governor from the manifest, the
// task store and the schema-validated request. The one agent-supplied value
// that reaches policy is the resource target, and the manifest loader only
// accepts a resource argument whose schema is enum- or pattern-bounded, so it
// is a selector, not a message.
//
// What this package must never do:
//   - Read the justification or the args body. (The args HASH is fine.)
//   - Turn a deny into an allow. Cedar makes this impossible; the test
//     TestForbidAlwaysWins documents it.
//   - Load a policy file without a valid signature.
//   - Call out to anything at decision time: no network, no model, no disk.
package policy

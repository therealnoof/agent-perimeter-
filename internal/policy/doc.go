// Package policy turns structural facts about a request into a verdict.
// Requirements P-2 and P-3.
//
// Week 1 ships the decision as plain Go so the rest of the governor can be
// built and tested against a real verdict type. Week 2 replaces the body of
// Decide with an embedded OPA evaluation of policies/*.rego; the Input and
// Verdict types stay the same, which is why they are defined here and not in
// the OPA code.
//
// The single most important property of this package is what Input does NOT
// contain: the agent's justification string, or any other free text the agent
// wrote. Input is built by the governor from the manifest, the task store and
// the schema-validated request. If a field is not in Input, policy cannot see
// it, and that is enforced by a reflection test rather than by convention.
//
// What this package must never do:
//   - Read the justification, the args body, or any string the agent authored.
//     (The args HASH is fine; the args themselves are not.)
//   - Turn a deny into an allow. Later stages may only tighten.
//   - Call out to anything: no network, no model, no file reads at decision time.
package policy

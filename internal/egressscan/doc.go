// Package egressscan looks for things that must not leave the perimeter
// inside the arguments of an outbound tool call. Requirement D-4 (egress).
//
// Three kinds of hit, in descending certainty:
//
//   - active: a value the governor itself issued and knows exactly: a
//     redaction placeholder it handed the worker in a tool result, or one
//     of its own token ids. These are not patterns, they are lookups; a hit
//     is certain and is a hard deny.
//   - high: a credential shape with a distinctive prefix or structure
//     (AWS access key, GitHub/Slack/Stripe tokens, a PEM private key
//     header, a bearer in a URL). Low false-positive rate; hard deny.
//   - low: generic shapes that are often secrets and often not (a 32+ hex
//     string, "api_key=…", a JWT-looking triple). Routed to a human.
//
// The scan runs on the canonical JSON of the arguments, so nested fields
// and arrays are covered without the scanner knowing the tool's schema. It
// never runs on the justification: that text goes nowhere, so there is
// nothing to protect it from.
//
// What this package must never do:
//   - Return the matched secret. Hits carry the rule name and the JSON path
//     of the field, never the value, because the hit goes into the audit
//     chain.
//   - Decide. It reports; policy (base.cedar) turns the report into a verdict.
package egressscan

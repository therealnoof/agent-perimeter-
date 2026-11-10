// Package approval is the human gate for "approve" verdicts. Requirement A-3.
//
// When policy says a human must confirm an action, the governor builds a
// Prompt from structural facts only (tool, target, taint, rule, args hash,
// task) and asks an Approver. The agent's justification text is carried
// but hidden: the approver must press a key to see it, and the prompt says
// so. The default view shows what the governor KNOWS, not what the agent
// SAYS, because the second is what a prompt-injected agent would use to
// talk the human into it.
//
// Rules:
//   - Unanswered prompts resolve to deny after the timeout (60 s default),
//     with reason_code approval_timeout. Silence is never consent.
//   - One prompt at a time. Further approve verdicts queue behind it.
//   - The decision and the approver's identity go into the audit chain.
//
// Three implementations:
//   - CLI: a prompt on the governor's terminal. The PoC's approver.
//   - DenyAll: for headless runs where no human is present.
//   - AllowAll: FOR TESTS ONLY. agentd refuses to start with it unless the
//     flag is spelled out in full, and logs a warning on every start.
//
// What this package must never do:
//   - Show the justification without an explicit keypress.
//   - Resolve to allow on timeout, EOF, or any error.
//   - Accept a decision from the worker's side of the socket.
package approval

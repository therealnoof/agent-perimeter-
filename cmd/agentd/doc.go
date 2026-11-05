// Command agentd is the governor: the one process that decides whether an AI
// agent's tool call runs.
//
// Usage:
//
//	agentd run -manifest M.json -pubkey K.pub -audit LOG.jsonl [-worker-uid N] [-dry-run] -- CMD ARGS...
//	agentd verify -audit LOG.jsonl
//
// `run` loads and verifies the manifest, spawns CMD as the untrusted worker
// with a socketpair on fd 3, and then serves requests until the worker exits
// or the kill switch fires. `verify` walks an audit chain and reports the
// first broken link, if any.
//
// What this binary must never do (G-5), enforced by imports_test.go:
//   - Import net/http or any network listener. The only I/O is the inherited
//     socketpair, files on local disk, and child processes it starts itself.
//   - Import any LLM SDK or call any model. Every decision is a function of
//     structural facts; no text the agent wrote is ever interpreted here.
//   - Parse the justification string. It is carried opaquely to the approval
//     prompt (week 3) and otherwise ignored.
package main

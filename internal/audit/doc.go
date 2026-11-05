// Package audit writes the governor's tamper-evident record of everything it
// decided and everything that happened as a result.
//
// The log is JSON Lines: one JSON object per line. Each record carries the
// SHA-256 of the previous record, so the file is a hash chain. Change one byte
// anywhere and every record after it stops verifying. Requirement A-1.
//
// The governor is the only writer (A-2). Executors report their outcome back
// to the governor over stdout/exit code and the governor writes it; they never
// touch this file. The worker container never has the log directory mounted.
//
// Every record carries the three-identity fields (A-5): who launched the
// governor (originating_user), which agent role asked (agent_role), and who
// approved, if anyone (approver_id). A public-sector reviewer asks "who"
// before "what", and this is where the answer lives.
//
// What this package must never do:
//   - Accept a record from anything but the governor process.
//   - Reorder, drop, or rewrite a record once appended.
//   - Block the request loop on fsync. Writes are batched with a bounded window.
package audit

// Package tokens mints and verifies the per-call capability token.
// Requirements C-1, C-2, C-3.
//
// A token is the governor's signed statement: "I authorized exactly this
// call, just now." It binds the tool, the resource target, the SHA-256 of
// the canonical arguments, and the task, and it expires in seconds. An
// executor (and the secrets sidecar) verifies it offline against the
// governor's public key before doing anything. There is no callback.
//
// Format: base64url(JSON claims) "." base64url(Ed25519 signature over the
// claims bytes). Two parts, one dot. Deliberately not JWT: no algorithm
// field to confuse, no header, nothing to negotiate.
//
// What the token is NOT: it is not where call counts, rate limits or task
// expiry live. Those are governor state (G-7). The token's expiry is short
// so that a captured token is worthless almost immediately; the governor's
// own counters are what stop a loop.
//
// Why not Biscuit: Biscuit's distinguishing feature is offline attenuation
// (a holder can derive a narrower token without calling home). Our tokens
// travel governor → executor and die in five seconds; nobody attenuates
// them. If agent-to-agent delegation is ever built, that path can use
// Biscuit behind the same Mint/Verify shape. Until then this is ~100 lines
// of standard library a reviewer can read in one sitting.
//
// What this package must never do:
//   - Mint without a signing key the governor generated or loaded itself.
//   - Accept a token whose signature, expiry, or binding does not check out,
//     for any reason, including "the clock looks wrong".
//   - Carry the arguments themselves. Only their hash.
package tokens

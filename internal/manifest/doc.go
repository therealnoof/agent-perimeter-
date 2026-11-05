// Package manifest loads and verifies the signed description of one agent role.
//
// A manifest says what an agent role is allowed to do: which tools it may
// call, how each tool's arguments must look, what data clearance it has, and
// whether it may delegate. It is the only source of those facts. The agent
// never sees the manifest and cannot change it.
//
// What this package must never do:
//   - Accept a manifest without a valid Ed25519 signature, in any mode.
//     Requirement G-1: a bad or missing signature means agentd does not start.
//   - Read anything from the network. Manifests are files on the governor's disk.
//   - Trust a public key supplied at runtime by anything other than the operator.
package manifest

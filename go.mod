module github.com/therealnoof/agent-perimeter

go 1.26.0

// Deliberately no third-party dependencies. The governor is the trust anchor
// for everything else in the system, so the less code it pulls in, the less
// there is to audit. Everything week 1 needs (Ed25519, socketpair, SO_PEERCRED,
// SHA-256, JSON) is in the Go standard library.

require github.com/cedar-policy/cedar-go v1.9.0

require (
	github.com/go-json-experiment/json v0.0.0-20260820222146-c27c302e5fc3 // indirect
	golang.org/x/exp v0.0.0-20220921023135-46d9e7742f1e // indirect
)

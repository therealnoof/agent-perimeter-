module github.com/therealnoof/agent-perimeter

go 1.23

// Deliberately no third-party dependencies. The governor is the trust anchor
// for everything else in the system, so the less code it pulls in, the less
// there is to audit. Everything week 1 needs (Ed25519, socketpair, SO_PEERCRED,
// SHA-256, JSON) is in the Go standard library.

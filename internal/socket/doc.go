// Package socket is the one channel between the untrusted worker and the
// governor. Requirements G-2 and G-3.
//
// How it works: the governor calls socketpair(2) to get two connected Unix
// sockets that exist only in memory. It keeps one end and hands the other to
// the worker process as an inherited file descriptor (fd 3). There is no
// socket file on disk, so there is nothing for another process to find,
// connect to, or race. When the worker exits, the pair is gone.
//
// Every message the governor reads carries kernel-attached sender credentials
// (SO_PASSCRED on our end, SCM_CREDENTIALS on each recvmsg). We check the UID
// only. We do NOT check the PID, because agent frameworks fork (shell tools,
// LangGraph subprocesses) and a child of the worker speaking on the inherited
// fd is legitimate. We reject the kernel overflow UID (65534), which is what
// the kernel reports when the sender's UID has no mapping in our user
// namespace: that is the signature of a container escape attempt or a
// misconfigured sandbox, and both should fail loudly.
//
// A note for anyone who reaches for SO_PEERCRED instead, as the PRD first
// did: SO_PEERCRED reports the credentials of the process that created the
// connection. For a socketpair that is the governor itself, so after the
// worker drops privileges SO_PEERCRED still says "root" and proves nothing.
// SCM_CREDENTIALS is per message and reflects the actual sender; the kernel
// fills it in and an unprivileged sender cannot forge it.
//
// Wire format: each frame is a 4-byte big-endian length followed by that many
// bytes of JSON. Length is capped (schema.MaxFrameBytes) before any allocation.
//
// What this package must never do:
//   - Open a filesystem Unix socket or any TCP listener.
//   - Accept a frame whose peer UID is not the one expected.
//   - Allocate based on an unchecked length from the peer.
package socket

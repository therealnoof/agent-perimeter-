// Package socket is the one channel between the untrusted worker and the
// governor. Requirements G-2 and G-3.
//
// How it works: the governor calls socketpair(2) to get two connected Unix
// sockets that exist only in memory. It keeps one end and hands the other to
// the worker process as an inherited file descriptor (fd 3). There is no
// socket file on disk, so there is nothing for another process to find,
// connect to, or race. When the worker exits, the pair is gone.
//
// Every frame the governor reads is checked against the peer's credentials
// via SO_PEERCRED. We check the UID only. We do NOT check the PID, because
// agent frameworks fork (shell tools, LangGraph subprocesses) and a child of
// the worker speaking on the inherited fd is legitimate. We reject the kernel
// overflow UID (65534), which is what SO_PEERCRED reports when the peer's UID
// has no mapping in our user namespace: that is the signature of a container
// escape attempt or a misconfigured sandbox, and both should fail loudly.
//
// Wire format: each frame is a 4-byte big-endian length followed by that many
// bytes of JSON. Length is capped (schema.MaxFrameBytes) before any allocation.
//
// What this package must never do:
//   - Open a filesystem Unix socket or any TCP listener.
//   - Accept a frame whose peer UID is not the one expected.
//   - Allocate based on an unchecked length from the peer.
package socket

package socket

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// localPair makes a socketpair inside this process. Both ends are us, so the
// kernel stamps our own UID on every message, which lets us test the happy
// path and the UID-mismatch path without spawning anything.
func localPair(t *testing.T, expectUID uint32) (*Pair, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	gov, err := FromFD(fds[0], expectUID, 1024)
	if err != nil {
		t.Fatal(err)
	}
	worker := os.NewFile(uintptr(fds[1]), "worker")
	t.Cleanup(func() { gov.Close(); worker.Close() })
	return gov, worker
}

func sendFrame(t *testing.T, w io.Writer, body []byte) {
	t.Helper()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTrip(t *testing.T) {
	gov, worker := localPair(t, uint32(os.Getuid()))
	sendFrame(t, worker, []byte(`{"hello":1}`))
	got, err := gov.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if string(got) != `{"hello":1}` {
		t.Errorf("got %q", got)
	}
	// And back the other way.
	if err := gov.WriteFrame([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	var hdr [4]byte
	io.ReadFull(worker, hdr[:])
	buf := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	io.ReadFull(worker, buf)
	if string(buf) != "ok" {
		t.Errorf("worker got %q", buf)
	}
}

// G-3: a sender whose UID is not the expected one is rejected on the very
// first message, before the frame body is read.
func TestWrongUIDRejected(t *testing.T) {
	me := uint32(os.Getuid())
	gov, worker := localPair(t, me+1) // expect someone else
	sendFrame(t, worker, []byte("x"))
	_, err := gov.ReadFrame()
	if !errors.Is(err, ErrPeerUID) {
		t.Fatalf("got %v, want ErrPeerUID", err)
	}
}

// G-3: the overflow UID (an unmapped sender) is rejected even when it is,
// absurdly, the expected UID. The decision function is tested directly.
func TestOverflowUIDRejected(t *testing.T) {
	if err := classifyUID(OverflowUID, OverflowUID); !errors.Is(err, ErrOverflowUID) {
		t.Fatalf("overflow == expected: got %v, want ErrOverflowUID", err)
	}
	if err := classifyUID(OverflowUID, 1000); !errors.Is(err, ErrOverflowUID) {
		t.Fatalf("overflow != expected: got %v, want ErrOverflowUID", err)
	}
	if err := classifyUID(1001, 1000); !errors.Is(err, ErrPeerUID) {
		t.Fatalf("mismatch: got %v, want ErrPeerUID", err)
	}
	if err := classifyUID(1000, 1000); err != nil {
		t.Fatalf("match: got %v, want nil", err)
	}
}

// A hostile length prefix must be rejected before allocation.
func TestOversizedFrameRejected(t *testing.T) {
	gov, worker := localPair(t, uint32(os.Getuid()))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0xFFFFFFFF)
	worker.Write(hdr[:])
	_, err := gov.ReadFrame()
	if !errors.Is(err, ErrFrameTooBig) {
		t.Fatalf("got %v, want ErrFrameTooBig", err)
	}
}

func TestZeroFrameRejected(t *testing.T) {
	gov, worker := localPair(t, uint32(os.Getuid()))
	worker.Write([]byte{0, 0, 0, 0})
	_, err := gov.ReadFrame()
	if !errors.Is(err, ErrFrameTooTiny) {
		t.Fatalf("got %v, want ErrFrameTooTiny", err)
	}
}

// Closing the worker end yields a clean EOF, not an error.
func TestEOFOnWorkerClose(t *testing.T) {
	gov, worker := localPair(t, uint32(os.Getuid()))
	worker.Close()
	_, err := gov.ReadFrame()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("got %v, want io.EOF", err)
	}
}

const childScript = `
import os, struct
body = b'{"from":"child"}'
os.write(3, struct.pack(">I", len(body)) + body)
`

// G-2 end to end: spawn a real child that writes a frame on fd 3.
func TestSpawnInheritsFD3(t *testing.T) {
	cmd := exec.Command("python3", "-c", childScript)
	p, err := Spawn(cmd, uint32(os.Getuid()), 1024)
	if err != nil {
		t.Skipf("spawn: %v (python3 missing?)", err)
	}
	defer p.Close()
	got, err := p.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if string(got) != `{"from":"child"}` {
		t.Errorf("got %q", got)
	}
	// After the child exits we must see EOF, proving we did not keep its end.
	if _, err := p.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("after child exit: got %v, want EOF", err)
	}
	p.Cmd.Wait()
}

// G-3 with a REAL privilege drop. Only runs as root (needed to setuid the
// child). The child runs as uid 12345; we expect 12345 and must accept, then
// expect 12346 and must reject. This is the case SO_PEERCRED got wrong.
func TestSpawnWithPrivilegeDrop(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to drop the child's privileges")
	}
	const childUID = 12345

	run := func(expect uint32) error {
		cmd := exec.Command("python3", "-c", childScript)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: childUID, Gid: childUID, NoSetGroups: true},
		}
		p, err := Spawn(cmd, expect, 1024)
		if err != nil {
			t.Fatalf("spawn: %v", err)
		}
		defer p.Close()
		defer p.Cmd.Wait()
		_, err = p.ReadFrame()
		return err
	}

	if err := run(childUID); err != nil {
		t.Fatalf("matching uid: got %v, want nil", err)
	}
	if err := run(childUID + 1); !errors.Is(err, ErrPeerUID) {
		t.Fatalf("mismatched uid: got %v, want ErrPeerUID", err)
	}
}

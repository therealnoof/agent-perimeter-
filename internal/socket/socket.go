package socket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
)

// OverflowUID is what the kernel reports for a peer whose UID is not mapped
// into our user namespace. Treat it as hostile.
const OverflowUID = 65534

// WorkerFD is the file descriptor number the worker finds its end of the
// socketpair on. 0,1,2 are stdio; 3 is the first free one.
const WorkerFD = 3

// Errors callers can test for.
var (
	ErrPeerUID      = errors.New("socket: sender UID does not match the worker")
	ErrOverflowUID  = errors.New("socket: sender UID is the overflow UID (unmapped)")
	ErrNoCreds      = errors.New("socket: message carried no kernel credentials")
	ErrFrameTooBig  = errors.New("socket: frame length exceeds limit")
	ErrFrameTooTiny = errors.New("socket: zero-length frame")
)

// Pair is the governor's end of a socketpair plus the worker that holds the
// other end.
type Pair struct {
	fd          int
	expectedUID uint32
	maxFrame    uint32
	Cmd         *exec.Cmd
}

// Spawn creates a socketpair, starts cmd with the worker end on fd 3, and
// returns the governor's side. expectedUID is the UID the worker runs as;
// every frame's kernel-attached sender credentials must match it.
//
// Why SO_PASSCRED and not SO_PEERCRED: SO_PEERCRED reports the credentials of
// the process that CREATED the connection. For a socketpair that is always
// the governor itself, even after the child calls setuid, so it proves
// nothing. With SO_PASSCRED set on our end, the kernel attaches the actual
// sender's uid/gid/pid to every message as SCM_CREDENTIALS ancillary data,
// and a sender cannot forge it without CAP_SETUID. That is the property G-3
// wants.
//
// The worker end is closed in our process immediately after the fork so that
// EOF on our side means the worker (and all its children) are gone.
func Spawn(cmd *exec.Cmd, expectedUID uint32, maxFrame uint32) (*Pair, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: socketpair: %w", err)
	}
	ours, theirs := fds[0], fds[1]

	if err := syscall.SetsockoptInt(ours, syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1); err != nil {
		syscall.Close(ours)
		syscall.Close(theirs)
		return nil, fmt.Errorf("socket: SO_PASSCRED: %w", err)
	}

	theirsFile := os.NewFile(uintptr(theirs), "worker-socket")
	// ExtraFiles[0] lands on fd 3 in the child, regardless of its fd number
	// here. Anything the caller already queued (the sandbox's seccomp
	// program) follows at fd 4, 5, ...
	cmd.ExtraFiles = append([]*os.File{theirsFile}, cmd.ExtraFiles...)

	if err := cmd.Start(); err != nil {
		theirsFile.Close()
		syscall.Close(ours)
		return nil, fmt.Errorf("socket: start worker: %w", err)
	}
	// We must not hold the worker's end, or we would never see EOF.
	theirsFile.Close()

	return &Pair{fd: ours, expectedUID: expectedUID, maxFrame: maxFrame, Cmd: cmd}, nil
}

// FromFD wraps an already-open socket fd as the governor side and enables
// SO_PASSCRED on it. Used by tests that build their own socketpair.
func FromFD(fd int, expectedUID uint32, maxFrame uint32) (*Pair, error) {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1); err != nil {
		return nil, fmt.Errorf("socket: SO_PASSCRED: %w", err)
	}
	return &Pair{fd: fd, expectedUID: expectedUID, maxFrame: maxFrame}, nil
}

// classifyUID is the whole G-3 decision in one pure function, so it can be
// tested without a second UID. Overflow is checked first: even if an operator
// misconfigured expectedUID to 65534, we still refuse.
func classifyUID(got, want uint32) error {
	if got == OverflowUID {
		return ErrOverflowUID
	}
	if got != want {
		return fmt.Errorf("%w: got %d, want %d", ErrPeerUID, got, want)
	}
	return nil
}

// recv reads up to len(buf) bytes with recvmsg and returns the bytes read and
// the sender UID from the SCM_CREDENTIALS the kernel attached. n == 0 means
// the peer closed.
func (p *Pair) recv(buf []byte) (int, uint32, error) {
	// Enough room for one SCM_CREDENTIALS message (12 bytes + header).
	oob := make([]byte, syscall.CmsgSpace(12))
	n, oobn, _, _, err := syscall.Recvmsg(p.fd, buf, oob, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("socket: recvmsg: %w", err)
	}
	if n == 0 {
		return 0, 0, nil
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return n, 0, fmt.Errorf("socket: parse control message: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Level == syscall.SOL_SOCKET && m.Header.Type == syscall.SCM_CREDENTIALS {
			cred, err := syscall.ParseUnixCredentials(&m)
			if err != nil {
				return n, 0, fmt.Errorf("socket: parse credentials: %w", err)
			}
			return n, cred.Uid, nil
		}
	}
	// With SO_PASSCRED set the kernel always attaches credentials. If they
	// are missing something is very wrong; refuse rather than guess.
	return n, 0, ErrNoCreds
}

// readFull reads exactly len(buf) bytes, checking the sender credentials on
// every message that arrives. Returns io.EOF if the peer closes before any
// byte, io.ErrUnexpectedEOF if it closes mid-frame.
func (p *Pair) readFull(buf []byte) error {
	got := 0
	for got < len(buf) {
		n, uid, err := p.recv(buf[got:])
		if err != nil {
			return err
		}
		if n == 0 {
			if got == 0 {
				return io.EOF
			}
			return io.ErrUnexpectedEOF
		}
		if err := classifyUID(uid, p.expectedUID); err != nil {
			return err
		}
		got += n
	}
	return nil
}

// ReadFrame reads one length-prefixed frame. Every message that makes up the
// frame is credential-checked (G-3). Returns io.EOF when the worker has
// closed its end.
func (p *Pair) ReadFrame() ([]byte, error) {
	var hdr [4]byte
	if err := p.readFull(hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF
		}
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	// Check the length BEFORE allocating. An unchecked 0xFFFFFFFF here is a
	// 4 GB allocation on demand from a hostile peer.
	if n == 0 {
		return nil, ErrFrameTooTiny
	}
	if n > p.maxFrame {
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooBig, n, p.maxFrame)
	}
	buf := make([]byte, n)
	if err := p.readFull(buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("socket: read body: %w", err)
	}
	return buf, nil
}

// WriteFrame sends one length-prefixed frame to the worker.
func (p *Pair) WriteFrame(b []byte) error {
	if uint32(len(b)) > p.maxFrame {
		return ErrFrameTooBig
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if err := writeAll(p.fd, hdr[:]); err != nil {
		return fmt.Errorf("socket: write header: %w", err)
	}
	if err := writeAll(p.fd, b); err != nil {
		return fmt.Errorf("socket: write body: %w", err)
	}
	return nil
}

func writeAll(fd int, b []byte) error {
	for len(b) > 0 {
		n, err := syscall.Write(fd, b)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		b = b[n:]
	}
	return nil
}

// Close shuts our end. If a worker was spawned, the caller is responsible for
// waiting on or killing Cmd.
func (p *Pair) Close() error {
	return syscall.Close(p.fd)
}

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
	ErrPeerUID      = errors.New("socket: peer UID does not match the worker")
	ErrOverflowUID  = errors.New("socket: peer UID is the overflow UID (unmapped)")
	ErrFrameTooBig  = errors.New("socket: frame length exceeds limit")
	ErrFrameTooTiny = errors.New("socket: zero-length frame")
)

// Pair is the governor's end of a socketpair plus the worker that holds the
// other end.
type Pair struct {
	conn        *os.File // our end, wrapped for Read/Write
	fd          int      // our end's raw fd, for getsockopt
	expectedUID uint32
	maxFrame    uint32
	Cmd         *exec.Cmd
}

// Spawn creates a socketpair, starts cmd with the worker end on fd 3, and
// returns the governor's side. expectedUID is the UID the worker runs as, as
// seen from our namespace; every frame's SO_PEERCRED must match it.
//
// The worker end is closed in our process immediately after the fork so that
// EOF on our side means the worker (and all its children) are gone.
func Spawn(cmd *exec.Cmd, expectedUID uint32, maxFrame uint32) (*Pair, error) {
	// SOCK_SEQPACKET would give us message boundaries for free, but SOCK_STREAM
	// plus a length prefix is what every language's stdlib can do without
	// ceremony, and the Python client has to be trivial.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: socketpair: %w", err)
	}
	ours, theirs := fds[0], fds[1]

	theirsFile := os.NewFile(uintptr(theirs), "worker-socket")
	// ExtraFiles[0] lands on fd 3 in the child, regardless of its fd number here.
	cmd.ExtraFiles = []*os.File{theirsFile}

	if err := cmd.Start(); err != nil {
		theirsFile.Close()
		syscall.Close(ours)
		return nil, fmt.Errorf("socket: start worker: %w", err)
	}
	// We must not hold the worker's end, or we would never see EOF.
	theirsFile.Close()

	return &Pair{
		conn:        os.NewFile(uintptr(ours), "governor-socket"),
		fd:          ours,
		expectedUID: expectedUID,
		maxFrame:    maxFrame,
		Cmd:         cmd,
	}, nil
}

// FromFD wraps an already-open socket fd as the governor side. Used by tests
// that build their own socketpair without spawning a process.
func FromFD(fd int, expectedUID uint32, maxFrame uint32) *Pair {
	return &Pair{
		conn:        os.NewFile(uintptr(fd), "governor-socket"),
		fd:          fd,
		expectedUID: expectedUID,
		maxFrame:    maxFrame,
	}
}

// PeerUID returns the UID of the process on the other end, via SO_PEERCRED.
func (p *Pair) PeerUID() (uint32, error) {
	ucred, err := syscall.GetsockoptUcred(p.fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("socket: SO_PEERCRED: %w", err)
	}
	return ucred.Uid, nil
}

// checkPeer enforces G-3 on every frame. Checking per frame rather than once
// at startup costs one getsockopt (microseconds) and means the check cannot
// be bypassed by a later change of identity on the far end.
func (p *Pair) checkPeer() error {
	uid, err := p.PeerUID()
	if err != nil {
		return err
	}
	return classifyUID(uid, p.expectedUID)
}

// classifyUID is the whole G-3 decision in one pure function, so it can be
// tested without a second user namespace. Overflow is checked first: even if
// an operator misconfigured expectedUID to 65534, we still refuse.
func classifyUID(got, want uint32) error {
	if got == OverflowUID {
		return ErrOverflowUID
	}
	if got != want {
		return fmt.Errorf("%w: got %d, want %d", ErrPeerUID, got, want)
	}
	return nil
}

// ReadFrame reads one length-prefixed frame after verifying the peer.
// Returns io.EOF when the worker has closed its end.
func (p *Pair) ReadFrame() ([]byte, error) {
	if err := p.checkPeer(); err != nil {
		return nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(p.conn, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("socket: read header: %w", err)
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
	if _, err := io.ReadFull(p.conn, buf); err != nil {
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
	if _, err := p.conn.Write(hdr[:]); err != nil {
		return fmt.Errorf("socket: write header: %w", err)
	}
	if _, err := p.conn.Write(b); err != nil {
		return fmt.Errorf("socket: write body: %w", err)
	}
	return nil
}

// Close shuts our end. If a worker was spawned, the caller is responsible for
// waiting on or killing Cmd.
func (p *Pair) Close() error {
	return p.conn.Close()
}

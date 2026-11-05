package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Record is one line of the audit chain. Field order is fixed by the struct so
// the JSON encoding is stable, which the hash depends on.
type Record struct {
	// Chain fields. Seq starts at 1. PrevHash is the hex SHA-256 of the
	// previous record's full JSON line (without the trailing newline); the
	// first record uses the all-zero genesis hash.
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Time     string `json:"time"` // RFC 3339 with nanoseconds, UTC

	// Three-identity record (A-5).
	OriginatingUser string `json:"originating_user"`
	AgentRole       string `json:"agent_role"`
	ApproverID      string `json:"approver_id,omitempty"`

	// What happened.
	Event  string `json:"event"`             // e.g. "start", "request", "verdict", "executor", "kill", "stop"
	TaskID string `json:"task_id,omitempty"` // the agent's task, when there is one
	Tool   string `json:"tool,omitempty"`
	Detail string `json:"detail,omitempty"` // free-form but governor-authored; never agent text

	// Decision fields, present on "verdict" events.
	Verdict    string `json:"verdict,omitempty"` // allow | deny | approve
	RuleFired  string `json:"rule_fired,omitempty"`
	ReasonCode string `json:"reason_code,omitempty"`
	TaintHWM   *int   `json:"taint_hwm,omitempty"`
	ArgsHash   string `json:"args_hash,omitempty"` // SHA-256 of canonical args; never the args themselves
	DryRun     bool   `json:"dry_run,omitempty"`

	// Executor outcome fields, present on "executor" events (A-2).
	TokenID  string `json:"token_id,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

// genesisHash is the prev_hash of the very first record.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Writer appends records to a chain. It is safe for concurrent use.
type Writer struct {
	mu       sync.Mutex
	f        *os.File
	bw       *bufio.Writer
	seq      uint64
	prevHash string

	// Batched fsync (A-1). Instead of fsync per record, we mark dirty and a
	// background goroutine syncs at most once per window. Close() does a
	// final sync.
	window time.Duration
	dirty  bool
	stop   chan struct{}
	done   chan struct{}
}

// Open opens (or creates) the chain at path for appending. If the file already
// has records, Open verifies the whole chain first and continues from its tail;
// a corrupt existing chain is refused rather than extended.
func Open(path string, fsyncWindow time.Duration) (*Writer, error) {
	if fsyncWindow <= 0 {
		fsyncWindow = 50 * time.Millisecond
	}

	// If there is an existing chain, verify it and pick up where it left off.
	seq, prev, err := tail(path)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}

	w := &Writer{
		f:        f,
		bw:       bufio.NewWriter(f),
		seq:      seq,
		prevHash: prev,
		window:   fsyncWindow,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go w.syncLoop()
	return w, nil
}

// Append writes one record, filling in seq, prev_hash and time. The caller
// fills everything else. Returns the record's own hash so callers (tests,
// the harness) can refer to it.
func (w *Writer) Append(r Record) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.seq++
	r.Seq = w.seq
	r.PrevHash = w.prevHash
	r.Time = time.Now().UTC().Format(time.RFC3339Nano)

	line, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("audit: marshal: %w", err)
	}
	if _, err := w.bw.Write(line); err != nil {
		return "", fmt.Errorf("audit: write: %w", err)
	}
	if err := w.bw.WriteByte('\n'); err != nil {
		return "", fmt.Errorf("audit: write: %w", err)
	}
	// Flush to the OS on every record so a crash loses at most what the
	// kernel had not yet written; fsync is what we batch.
	if err := w.bw.Flush(); err != nil {
		return "", fmt.Errorf("audit: flush: %w", err)
	}

	h := hashLine(line)
	w.prevHash = h
	w.dirty = true
	return h, nil
}

// Close flushes, does a final fsync, and closes the file.
func (w *Writer) Close() error {
	close(w.stop)
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.bw.Flush(); err != nil {
		return err
	}
	if err := w.f.Sync(); err != nil {
		return err
	}
	return w.f.Close()
}

// syncLoop fsyncs at most once per window while there is dirty data.
func (w *Writer) syncLoop() {
	defer close(w.done)
	t := time.NewTicker(w.window)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.mu.Lock()
			if w.dirty {
				_ = w.f.Sync()
				w.dirty = false
			}
			w.mu.Unlock()
		}
	}
}

// hashLine returns the hex SHA-256 of one JSON line (no trailing newline).
func hashLine(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// ErrChainBroken is returned by Verify with the failing sequence number.
type ErrChainBroken struct {
	Seq    uint64
	Reason string
}

func (e *ErrChainBroken) Error() string {
	return fmt.Sprintf("audit: chain broken at record %d: %s", e.Seq, e.Reason)
}

// Verify walks the chain at path and returns the number of records if every
// link holds. It returns *ErrChainBroken naming the first bad record otherwise.
func Verify(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("audit: open %s: %w", path, err)
	}
	defer f.Close()
	return verifyReader(f)
}

// verifyReader is Verify over any reader, for tests and for tail().
func verifyReader(r io.Reader) (uint64, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // allow long records

	var (
		expectSeq  uint64 = 1
		expectPrev        = genesisHash
	)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Seq      uint64 `json:"seq"`
			PrevHash string `json:"prev_hash"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return 0, &ErrChainBroken{Seq: expectSeq, Reason: "not valid JSON"}
		}
		if rec.Seq != expectSeq {
			return 0, &ErrChainBroken{Seq: expectSeq, Reason: fmt.Sprintf("seq is %d, expected %d", rec.Seq, expectSeq)}
		}
		if rec.PrevHash != expectPrev {
			return 0, &ErrChainBroken{Seq: expectSeq, Reason: "prev_hash does not match previous record"}
		}
		// Copy the line: the scanner reuses its buffer.
		expectPrev = hashLine(append([]byte(nil), line...))
		expectSeq++
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("audit: read: %w", err)
	}
	return expectSeq - 1, nil
}

// tail verifies an existing chain and returns (lastSeq, lastHash). For a
// missing or empty file it returns (0, genesis).
func tail(path string) (uint64, string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, genesisHash, nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("audit: open %s: %w", path, err)
	}
	defer f.Close()

	// Verify first; refuse to extend a broken chain.
	n, err := verifyReader(f)
	if err != nil {
		return 0, "", err
	}
	if n == 0 {
		return 0, genesisHash, nil
	}

	// Re-read to get the last line's hash. Files are small in the PoC; a
	// production version would keep the tail hash in a sidecar.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var last []byte
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			last = append(last[:0], sc.Bytes()...)
		}
	}
	return n, hashLine(last), nil
}

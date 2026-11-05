package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeChain(t *testing.T, path string, n int) {
	t.Helper()
	w, err := Open(path, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		_, err := w.Append(Record{
			OriginatingUser: "tester",
			AgentRole:       "test-role",
			Event:           "request",
			TaskID:          "t1",
			Tool:            "echo",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyCleanChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	writeChain(t, p, 25)
	n, err := Verify(p)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if n != 25 {
		t.Errorf("n = %d, want 25", n)
	}
}

// A-1: editing one byte in the middle of the file must be detected, and the
// report must name the first record after the edit.
func TestVerifyDetectsEditedByte(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	writeChain(t, p, 10)

	raw, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// Change the tool name in record 4 (index 3). This keeps the JSON valid,
	// which is the subtle case: the record still parses, but its hash changes,
	// so record 5's prev_hash no longer matches.
	lines[3] = strings.Replace(lines[3], `"tool":"echo"`, `"tool":"ECHO"`, 1)
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Verify(p)
	var cb *ErrChainBroken
	if !errors.As(err, &cb) {
		t.Fatalf("got %v, want ErrChainBroken", err)
	}
	if cb.Seq != 5 {
		t.Errorf("broken at seq %d, want 5", cb.Seq)
	}
}

// Deleting a record must be detected (sequence gap).
func TestVerifyDetectsDeletedRecord(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	writeChain(t, p, 6)
	raw, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	lines = append(lines[:2], lines[3:]...) // drop record 3
	os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	_, err := Verify(p)
	var cb *ErrChainBroken
	if !errors.As(err, &cb) || cb.Seq != 3 {
		t.Fatalf("got %v, want chain broken at 3", err)
	}
}

// Reopening an existing chain continues it rather than starting over.
func TestReopenContinuesChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	writeChain(t, p, 3)
	writeChain(t, p, 2)
	n, err := Verify(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
}

// Reopening a corrupt chain must be refused; we never extend a bad chain.
func TestReopenRefusesBrokenChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	writeChain(t, p, 3)
	raw, _ := os.ReadFile(p)
	raw[10] ^= 0xff
	os.WriteFile(p, raw, 0o600)
	_, err := Open(p, 0)
	if err == nil {
		t.Fatal("Open succeeded on a broken chain")
	}
}

package taskstate

import (
	"sync"
	"testing"
)

func TestCallCounts(t *testing.T) {
	s := New()
	if s.Count("t1", "echo") != 0 {
		t.Fatal("fresh task should have zero calls")
	}
	s.RecordAllow("t1", "echo")
	s.RecordAllow("t1", "echo")
	s.RecordAllow("t1", "other")
	if got := s.Count("t1", "echo"); got != 2 {
		t.Errorf("echo count = %d, want 2", got)
	}
	if got := s.Count("t2", "echo"); got != 0 {
		t.Errorf("other task leaked count: %d", got)
	}
}

// D-2: the taint mark only rises.
func TestTaintNeverFalls(t *testing.T) {
	s := New()
	s.RaiseTaint("t1", 3)
	s.RaiseTaint("t1", 8)
	s.RaiseTaint("t1", 2) // lower: must be ignored
	if got := s.TaintHWM("t1"); got != 8 {
		t.Errorf("taint = %d, want 8", got)
	}
}

// G-7: concurrent updates from many goroutines are counted exactly.
func TestConcurrentCounts(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.RecordAllow("t1", "echo")
		}()
	}
	wg.Wait()
	if got := s.Count("t1", "echo"); got != 500 {
		t.Errorf("count = %d, want 500", got)
	}
}

func TestForget(t *testing.T) {
	s := New()
	s.RecordAllow("t1", "echo")
	s.Forget("t1")
	if s.Count("t1", "echo") != 0 {
		t.Error("forgotten task retained state")
	}
}

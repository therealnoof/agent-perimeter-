package taskstate

import (
	"sync"
	"time"
)

// Task is the governor's view of one agent task.
type Task struct {
	ID        string
	StartedAt time.Time

	// callCounts[tool] = how many times this tool has been ALLOWED in this
	// task. Denied and pending-approval calls do not count.
	callCounts map[string]int

	// taintHWM is the highest sensitivity level of any data this task has
	// received. 0 means nothing sensitive yet. It only ever goes up.
	taintHWM int

	// Delegation (G-8). ParentTaskID is empty for a root task.
	ParentTaskID    string
	DelegationDepth int
}

// Store holds all live tasks. Safe for concurrent use.
type Store struct {
	mu    sync.Mutex
	tasks map[string]*Task
	now   func() time.Time // injectable for tests
}

// New returns an empty store.
func New() *Store {
	return &Store{tasks: map[string]*Task{}, now: time.Now}
}

// Get returns the task, creating it on first sight. A task is created by the
// governor the first time it sees a task_id; the worker does not "open" tasks.
func (s *Store) Get(id string) *Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		t = &Task{ID: id, StartedAt: s.now(), callCounts: map[string]int{}}
		s.tasks[id] = t
	}
	return t
}

// Count returns how many times tool has been allowed in the task.
func (s *Store) Count(taskID, tool string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(taskID).callCounts[tool]
}

// RecordAllow increments the call count for tool and returns the new count.
// Call this only after the verdict is "allow".
func (s *Store) RecordAllow(taskID, tool string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.get(taskID)
	t.callCounts[tool]++
	return t.callCounts[tool]
}

// TaintHWM returns the task's current taint high-water mark.
func (s *Store) TaintHWM(taskID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(taskID).taintHWM
}

// RaiseTaint raises the mark to level if level is higher. It never lowers it.
// Returns the mark after the call. The governor calls this when it returns a
// tool result whose source has a known sensitivity.
func (s *Store) RaiseTaint(taskID string, level int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.get(taskID)
	if level > t.taintHWM {
		t.taintHWM = level
	}
	return t.taintHWM
}

// Elapsed returns how long the task has been running.
func (s *Store) Elapsed(taskID string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now().Sub(s.get(taskID).StartedAt)
}

// Delegation returns (parent, depth) for the task.
func (s *Store) Delegation(taskID string) (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.get(taskID)
	return t.ParentTaskID, t.DelegationDepth
}

// Forget drops a finished task. Memory hygiene only; nothing reads it after.
func (s *Store) Forget(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tasks, taskID)
}

// get is Get without locking, for use by methods that already hold the lock.
func (s *Store) get(id string) *Task {
	t, ok := s.tasks[id]
	if !ok {
		t = &Task{ID: id, StartedAt: s.now(), callCounts: map[string]int{}}
		s.tasks[id] = t
	}
	return t
}

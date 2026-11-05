// Package taskstate owns every piece of mutable per-task state in the
// governor. Requirement G-7.
//
// The design rule is simple: if a number can change during a task and a
// policy decision depends on it, it lives here and nowhere else. The client
// library never reports it, executors never hold it, and tokens never carry
// it. That is what makes "the agent cannot influence the decision" true
// rather than aspirational.
//
// What lives here:
//   - Call counts per tool, so a loop of 200 jira_update calls dies at the cap.
//   - The taint high-water mark (D-2): once any untrusted data has entered the
//     task, the mark rises and never falls for the life of the task.
//   - Delegation depth and parent task (G-8), tracked but never incremented in
//     the PoC.
//   - Task start time, for expiry.
//
// What this package must never do:
//   - Accept a label, count, or taint value from the worker or an executor.
//     Only the governor's own code paths call the mutators.
//   - Let the taint mark go down.
package taskstate

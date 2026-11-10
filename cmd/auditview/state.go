package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/therealnoof/agent-perimeter/internal/audit"
)

// State is the whole dashboard model, sent as one JSON document. Built from
// the audit chain (authoritative), the sidecar log and the mock log.
type State struct {
	GeneratedAt string `json:"generated_at"`

	Chain struct {
		OK         bool   `json:"ok"`
		Records    uint64 `json:"records"`
		Error      string `json:"error,omitempty"`
		VerifiedAt string `json:"verified_at"`
		Path       string `json:"path"`
	} `json:"chain"`

	// From the latest "start" record.
	Governor struct {
		Role            string `json:"role"`
		OriginatingUser string `json:"originating_user"`
		Detail          string `json:"detail"`
		WorkerCmd       string `json:"worker_cmd"`
		WorkerExeSHA    string `json:"worker_exe_sha256"`
		WorkerScriptSHA string `json:"worker_script_sha256"`
		StartedAt       string `json:"started_at"`
		Runs            int    `json:"runs"` // how many start records the chain holds
	} `json:"governor"`

	Requests  []Request  `json:"requests"`  // one per req_id, oldest first
	Taint     []Point    `json:"taint"`     // taint over time
	Approvals []Approval `json:"approvals"` // every approval record
	Releases  []Release  `json:"releases"`  // sidecar events, joined to executor records
	Services  []string   `json:"services"`  // mock log lines
	Lifecycle []Event    `json:"lifecycle"` // start/stop/kill/reject
	Profile   Profile    `json:"profile"`
}

type Point struct {
	T     string `json:"t"`
	Taint int    `json:"taint"`
	ReqID string `json:"req_id,omitempty"`
}

type Request struct {
	ReqID    string `json:"req_id"`
	Seq      uint64 `json:"seq"`
	Time     string `json:"time"`
	TaskID   string `json:"task_id"`
	Tool     string `json:"tool"`
	Target   string `json:"target"`
	ArgsHash string `json:"args_hash"`
	Client   string `json:"client,omitempty"`
	JLen     int    `json:"j_len"`

	Verdict    string `json:"verdict"` // allow | deny | approve | rejected
	Rule       string `json:"rule"`
	ReasonCode string `json:"reason_code,omitempty"`
	TaintAt    int    `json:"taint_at"` // taint when decided
	DryRun     bool   `json:"dry_run,omitempty"`

	// Final outcome after approval and execution.
	Outcome    string `json:"outcome"` // executed | denied | pending_timeout | declined | approved_then_failed | rejected
	Approval   *ApprovalInfo `json:"approval,omitempty"`
	Executor   *ExecInfo     `json:"executor,omitempty"`
	RejectWhy  string        `json:"reject_why,omitempty"`

	// Span timings.
	SchemaUS   int64 `json:"t_schema_us"`
	PolicyUS   int64 `json:"t_policy_us"`
	ApprovalMS int64 `json:"t_approval_ms"`
	ExecMS     int64 `json:"t_exec_ms"`
	TotalUS    int64 `json:"t_total_us"`
}

type ApprovalInfo struct {
	Decision   string `json:"decision"` // approved | declined
	ApproverID string `json:"approver_id"`
	ReasonCode string `json:"reason_code"`
	WaitMS     int64  `json:"wait_ms"`
}

type ExecInfo struct {
	TokenID    string `json:"token_id"`
	ExitCode   int    `json:"exit_code"`
	TaintAfter int    `json:"taint_after"`
	Detail     string `json:"detail"`
	Released   bool   `json:"released"` // the sidecar logged a release for this token
}

type Approval struct {
	Time       string `json:"time"`
	ReqID      string `json:"req_id"`
	Tool       string `json:"tool"`
	Target     string `json:"target"`
	Rule       string `json:"rule"`
	Decision   string `json:"decision"`
	ApproverID string `json:"approver_id"`
	ReasonCode string `json:"reason_code"`
	WaitMS     int64  `json:"wait_ms"`
}

type Release struct {
	TS      string `json:"ts"`
	Event   string `json:"event"` // released | refused | error
	Tool    string `json:"tool"`
	TaskID  string `json:"task_id,omitempty"`
	TokenID string `json:"token_id,omitempty"`
	Path    string `json:"path,omitempty"`
	Error   string `json:"error,omitempty"`
	ReqID   string `json:"req_id,omitempty"` // joined via executor record
}

type Event struct {
	Time   string `json:"time"`
	Seq    uint64 `json:"seq"`
	Event  string `json:"event"`
	Detail string `json:"detail"`
}

// Profile is the behavioural fingerprint: shape, never content.
type Profile struct {
	Requests        int            `json:"requests"`
	ToolMix         map[string]int `json:"tool_mix"`
	VerdictMix      map[string]int `json:"verdict_mix"`
	Sequence        []string       `json:"sequence"` // tool names in order, last 40
	Bigrams         map[string]int `json:"bigrams"`  // "a→b" counts
	DistinctTargets int            `json:"distinct_targets"`
	UnknownTool     int            `json:"unknown_tool_attempts"`
	SchemaRejects   int            `json:"schema_rejects"`
	RetryAfterDeny  int            `json:"retry_after_deny"` // same tool+args hash re-proposed after a deny
	ApproveVerdicts int            `json:"approve_verdicts"`
	PostTaintOut    int            `json:"outbound_after_taint"` // outbound attempts after taint >= 7
	JLenBeforeDeny  float64        `json:"jlen_mean"`
	JLenAfterDeny   float64        `json:"jlen_mean_after_deny"`
	GapMS           []int64        `json:"gap_ms"` // inter-request gaps, last 40
	GapP50MS        int64          `json:"gap_p50_ms"`
	PolicyP95US     int64          `json:"policy_p95_us"`
	TotalP95US      int64          `json:"total_p95_us"`
	Clients         map[string]int `json:"clients"`
	Flags           []Flag         `json:"flags"`
}

type Flag struct {
	Severity string `json:"severity"` // info | warn | high
	Text     string `json:"text"`
	ReqIDs   []string `json:"req_ids,omitempty"`
}

// --- watcher -----------------------------------------------------------------------

type watcher struct {
	auditPath, secretsLog, mockAddr string
	poll                            time.Duration

	mu      sync.RWMutex
	state   State
	stateJS []byte
	version uint64

	subsMu sync.Mutex
	subs   map[chan []byte]struct{}
}

func newWatcher(auditPath, secretsLog, mockAddr string, poll time.Duration) *watcher {
	return &watcher{auditPath: auditPath, secretsLog: secretsLog, mockAddr: mockAddr, poll: poll, subs: map[chan []byte]struct{}{}}
}

// run rebuilds the state whenever a source changes and pushes it to
// subscribers. Sources are small files; rebuilding from scratch each time is
// simpler than incremental parsing and keeps the chain verification honest.
func (w *watcher) run() {
	var lastSig string
	for {
		sig := w.signature()
		if sig != lastSig {
			lastSig = sig
			st := w.build()
			js, _ := json.Marshal(st)
			w.mu.Lock()
			w.state, w.stateJS = st, js
			w.version++
			w.mu.Unlock()
			w.broadcast(js)
		}
		time.Sleep(w.poll)
	}
}

// signature changes when any source changes: file sizes + mtimes, plus the
// mock log length.
func (w *watcher) signature() string {
	var b strings.Builder
	for _, p := range []string{w.auditPath, w.secretsLog} {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", p, st.Size(), st.ModTime().UnixNano())
		}
	}
	if w.mockAddr != "" {
		if lines := fetchMockLog(w.mockAddr); lines != nil {
			fmt.Fprintf(&b, "mock:%d;", len(lines))
		}
	}
	return b.String()
}

func (w *watcher) build() State {
	var st State
	st.GeneratedAt = time.Now().UTC().Format(time.RFC3339Nano)
	st.Chain.Path = w.auditPath

	n, err := audit.Verify(w.auditPath)
	st.Chain.Records = n
	st.Chain.OK = err == nil
	st.Chain.VerifiedAt = st.GeneratedAt
	if err != nil {
		st.Chain.Error = err.Error()
	}

	recs := readChain(w.auditPath)
	buildRequests(&st, recs)
	st.Releases = readReleases(w.secretsLog)
	joinReleases(&st)
	if w.mockAddr != "" {
		st.Services = fetchMockLog(w.mockAddr)
	}
	st.Profile = profile(st.Requests)
	return st
}

// readChain parses every record, tolerating a broken chain (we still show
// what is there; the header says it is not trustworthy).
func readChain(path string) []audit.Record {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []audit.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var r audit.Record
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

func buildRequests(st *State, recs []audit.Record) {
	byReq := map[string]*Request{}
	var order []string
	for _, r := range recs {
		switch r.Event {
		case "start":
			st.Governor.Runs++
			st.Governor.Role = r.AgentRole
			st.Governor.OriginatingUser = r.OriginatingUser
			st.Governor.Detail = r.Detail
			st.Governor.WorkerCmd = r.WorkerCmd
			st.Governor.WorkerExeSHA = r.WorkerExeSHA256
			st.Governor.WorkerScriptSHA = r.WorkerScriptSHA256
			st.Governor.StartedAt = r.Time
			st.Lifecycle = append(st.Lifecycle, Event{r.Time, r.Seq, r.Event, r.Detail})
		case "stop", "kill":
			st.Lifecycle = append(st.Lifecycle, Event{r.Time, r.Seq, r.Event, r.Detail})
		}
		if r.ReqID == "" {
			continue
		}
		q, ok := byReq[r.ReqID]
		if !ok {
			q = &Request{ReqID: r.ReqID, Seq: r.Seq, Time: r.Time, TaskID: r.TaskID}
			byReq[r.ReqID] = q
			order = append(order, r.ReqID)
		}
		if r.Tool != "" {
			q.Tool = r.Tool
		}
		if r.Target != "" {
			q.Target = r.Target
		}
		if r.ArgsHash != "" {
			q.ArgsHash = r.ArgsHash
		}
		if r.Client != "" {
			q.Client = r.Client
		}
		if r.JustificationLen > 0 {
			q.JLen = r.JustificationLen
		}
		// Timings: the last record for a request has the fullest picture.
		q.SchemaUS, q.PolicyUS, q.ApprovalMS, q.ExecMS, q.TotalUS = r.SchemaUS, r.PolicyUS, r.ApprovalMS, r.ExecMS, r.TotalUS

		switch r.Event {
		case "reject":
			q.Verdict = "rejected"
			q.Outcome = "rejected"
			q.RejectWhy = r.Detail
			q.ReasonCode = r.ReasonCode
		case "verdict":
			q.Verdict = r.Verdict
			q.Rule = r.RuleFired
			q.ReasonCode = r.ReasonCode
			q.DryRun = r.DryRun
			if r.TaintHWM != nil {
				q.TaintAt = *r.TaintHWM
				st.Taint = append(st.Taint, Point{r.Time, *r.TaintHWM, r.ReqID})
			}
			switch r.Verdict {
			case "deny":
				q.Outcome = "denied"
			case "approve":
				q.Outcome = "pending"
			default:
				q.Outcome = "allowed"
			}
		case "approval":
			q.Approval = &ApprovalInfo{Decision: r.Verdict, ApproverID: r.ApproverID, ReasonCode: r.ReasonCode, WaitMS: r.ApprovalMS}
			st.Approvals = append(st.Approvals, Approval{r.Time, r.ReqID, r.Tool, r.Target, r.RuleFired, r.Verdict, r.ApproverID, r.ReasonCode, r.ApprovalMS})
			if r.Verdict == "approved" {
				q.Outcome = "approved"
			} else if r.ReasonCode == "approval_timeout" {
				q.Outcome = "pending_timeout"
			} else {
				q.Outcome = "declined"
			}
		case "executor":
			ex := &ExecInfo{TokenID: r.TokenID, Detail: r.Detail}
			if r.ExitCode != nil {
				ex.ExitCode = *r.ExitCode
			}
			if r.TaintHWM != nil {
				ex.TaintAfter = *r.TaintHWM
				st.Taint = append(st.Taint, Point{r.Time, *r.TaintHWM, r.ReqID})
			}
			q.Executor = ex
			if ex.ExitCode == 0 {
				q.Outcome = "executed"
			} else {
				q.Outcome = "approved_then_failed"
				if q.Approval == nil {
					q.Outcome = "exec_failed"
				}
			}
		}
	}
	for _, id := range order {
		st.Requests = append(st.Requests, *byReq[id])
	}
}

// readReleases parses the sidecar's JSON lines, ignoring anything that is
// not one (its startup text, for instance).
func readReleases(path string) []Release {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Release
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r Release
		if json.Unmarshal([]byte(line), &r) == nil && r.Event != "" {
			out = append(out, r)
		}
	}
	return out
}

// joinReleases links sidecar events to requests by token id, both ways.
func joinReleases(st *State) {
	byTok := map[string]int{}
	for i := range st.Requests {
		if ex := st.Requests[i].Executor; ex != nil && ex.TokenID != "" {
			byTok[ex.TokenID] = i
		}
	}
	for i := range st.Releases {
		if idx, ok := byTok[st.Releases[i].TokenID]; ok {
			st.Releases[i].ReqID = st.Requests[idx].ReqID
			if st.Releases[i].Event == "released" {
				st.Requests[idx].Executor.Released = true
			}
		}
	}
}

func fetchMockLog(addr string) []string {
	c := &http.Client{Timeout: 400 * time.Millisecond}
	resp, err := c.Get("http://" + addr + "/log")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	s := strings.TrimSpace(string(b))
	if s == "" {
		return []string{}
	}
	return strings.Split(s, "\n")
}

// --- behavioural profile -------------------------------------------------------------

func profile(reqs []Request) Profile {
	p := Profile{ToolMix: map[string]int{}, VerdictMix: map[string]int{}, Bigrams: map[string]int{}, Clients: map[string]int{}}
	p.Requests = len(reqs)
	targets := map[string]bool{}
	seenArgs := map[string]string{} // tool+hash -> last verdict
	var jBefore, jAfter []float64
	var policyUS, totalUS []int64
	var gaps []int64
	var prevT time.Time
	deniedOnce := false
	var retryIDs, unknownIDs, postTaintIDs []string

	for i, q := range reqs {
		p.ToolMix[q.Tool]++
		p.VerdictMix[q.Verdict]++
		if q.Client != "" {
			p.Clients[q.Client]++
		}
		if q.Target != "" && q.Target != "-" {
			targets[q.Target] = true
		}
		if i > 0 && reqs[i-1].Tool != "" && q.Tool != "" {
			p.Bigrams[reqs[i-1].Tool+"→"+q.Tool]++
		}
		if q.Rule == "base.unknown_tool" {
			p.UnknownTool++
			unknownIDs = append(unknownIDs, q.ReqID)
		}
		if q.Verdict == "rejected" && q.ReasonCode == "schema" {
			p.SchemaRejects++
		}
		if q.Verdict == "approve" {
			p.ApproveVerdicts++
		}
		key := q.Tool + "|" + q.ArgsHash
		if prev, ok := seenArgs[key]; ok && prev == "deny" {
			p.RetryAfterDeny++
			retryIDs = append(retryIDs, q.ReqID)
		}
		seenArgs[key] = q.Verdict
		if q.TaintAt >= 7 && (q.Rule == "flow.sensitivity_floor" || q.Rule == "flow.freeform_outbound" || strings.HasPrefix(q.Tool, "slack_") || strings.HasSuffix(q.Tool, "_update")) {
			p.PostTaintOut++
			postTaintIDs = append(postTaintIDs, q.ReqID)
		}
		if deniedOnce {
			jAfter = append(jAfter, float64(q.JLen))
		} else {
			jBefore = append(jBefore, float64(q.JLen))
		}
		if q.Verdict == "deny" {
			deniedOnce = true
		}
		if q.PolicyUS > 0 {
			policyUS = append(policyUS, q.PolicyUS)
		}
		if q.TotalUS > 0 {
			totalUS = append(totalUS, q.TotalUS)
		}
		if t, err := time.Parse(time.RFC3339Nano, q.Time); err == nil {
			if !prevT.IsZero() {
				gaps = append(gaps, t.Sub(prevT).Milliseconds())
			}
			prevT = t
		}
	}
	p.DistinctTargets = len(targets)
	p.JLenBeforeDeny = mean(jBefore)
	p.JLenAfterDeny = mean(jAfter)
	p.PolicyP95US = p95(policyUS)
	p.TotalP95US = p95(totalUS)
	p.GapP50MS = p50(gaps)
	if len(gaps) > 40 {
		gaps = gaps[len(gaps)-40:]
	}
	p.GapMS = gaps
	for _, q := range reqs {
		p.Sequence = append(p.Sequence, q.Tool)
	}
	if len(p.Sequence) > 40 {
		p.Sequence = p.Sequence[len(p.Sequence)-40:]
	}

	// Flags: plain-English, each pointing at the records behind it. These
	// are the week-3.5 heuristics; week 5 replaces the thresholds with
	// per-role baselines from benign runs.
	if p.UnknownTool > 0 {
		p.Flags = append(p.Flags, Flag{"warn", fmt.Sprintf("%d attempt(s) at tools not in the manifest", p.UnknownTool), unknownIDs})
	}
	if p.RetryAfterDeny > 0 {
		sev := "warn"
		txt := fmt.Sprintf("%d identical call(s) re-proposed after a deny", p.RetryAfterDeny)
		if p.JLenBeforeDeny > 0 && p.JLenAfterDeny > 3*p.JLenBeforeDeny {
			sev = "high"
			txt += fmt.Sprintf("; justification length %.0f× higher after the first deny (persuasion pattern)", p.JLenAfterDeny/p.JLenBeforeDeny)
		}
		p.Flags = append(p.Flags, Flag{sev, txt, retryIDs})
	} else if p.JLenBeforeDeny > 0 && p.JLenAfterDeny > 3*p.JLenBeforeDeny {
		p.Flags = append(p.Flags, Flag{"warn", fmt.Sprintf("justification length %.0f× higher after the first deny", p.JLenAfterDeny/p.JLenBeforeDeny), nil})
	}
	if p.PostTaintOut > 0 {
		p.Flags = append(p.Flags, Flag{"high", fmt.Sprintf("%d outbound attempt(s) after the task touched sensitive data (taint ≥ 7)", p.PostTaintOut), postTaintIDs})
	}
	if p.SchemaRejects > 0 {
		p.Flags = append(p.Flags, Flag{"warn", fmt.Sprintf("%d request(s) with arguments the tool schema does not allow", p.SchemaRejects), nil})
	}
	if len(p.Clients) > 1 {
		p.Flags = append(p.Flags, Flag{"warn", fmt.Sprintf("%d different client identities on one socket", len(p.Clients)), nil})
	}
	if p.TotalP95US > 5000 && p.ApproveVerdicts == 0 {
		p.Flags = append(p.Flags, Flag{"info", fmt.Sprintf("p95 governor time %d µs exceeds the 5 ms budget (includes executor runtime)", p.TotalP95US), nil})
	}
	return p
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func pct(xs []int64, q float64) int64 {
	if len(xs) == 0 {
		return 0
	}
	c := append([]int64(nil), xs...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	i := int(math.Ceil(q*float64(len(c)))) - 1
	if i < 0 {
		i = 0
	}
	return c[i]
}
func p95(xs []int64) int64 { return pct(xs, 0.95) }
func p50(xs []int64) int64 { return pct(xs, 0.50) }

// --- HTTP ----------------------------------------------------------------------------

func (w *watcher) serveState(rw http.ResponseWriter, r *http.Request) {
	w.mu.RLock()
	js := w.stateJS
	w.mu.RUnlock()
	if js == nil {
		js = []byte(`{"chain":{"ok":false,"error":"no data yet"}}`)
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(js)
}

// serveEvents is Server-Sent Events: the full state on connect and on every
// change. The page is small enough that sending the whole document beats
// diffing.
func (w *watcher) serveEvents(rw http.ResponseWriter, r *http.Request) {
	fl, ok := rw.(http.Flusher)
	if !ok {
		http.Error(rw, "streaming unsupported", 500)
		return
	}
	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Connection", "keep-alive")

	ch := make(chan []byte, 4)
	w.subsMu.Lock()
	w.subs[ch] = struct{}{}
	w.subsMu.Unlock()
	defer func() {
		w.subsMu.Lock()
		delete(w.subs, ch)
		w.subsMu.Unlock()
	}()

	w.mu.RLock()
	if w.stateJS != nil {
		fmt.Fprintf(rw, "data: %s\n\n", w.stateJS)
		fl.Flush()
	}
	w.mu.RUnlock()

	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case js := <-ch:
			fmt.Fprintf(rw, "data: %s\n\n", js)
			fl.Flush()
		case <-keep.C:
			fmt.Fprint(rw, ": keepalive\n\n")
			fl.Flush()
		}
	}
}

func (w *watcher) broadcast(js []byte) {
	w.subsMu.Lock()
	defer w.subsMu.Unlock()
	for ch := range w.subs {
		select {
		case ch <- js:
		default: // slow client; it will catch up on the next change
		}
	}
}

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/therealnoof/agent-perimeter/internal/audit"
	"github.com/therealnoof/agent-perimeter/internal/manifest"
	"github.com/therealnoof/agent-perimeter/internal/policy"
	"github.com/therealnoof/agent-perimeter/internal/schema"
	"github.com/therealnoof/agent-perimeter/internal/socket"
	"github.com/therealnoof/agent-perimeter/internal/taskstate"
)

// verifyChain is a thin alias so main.go does not import audit directly.
func verifyChain(path string) (uint64, error) { return audit.Verify(path) }

// response is the frame sent back to the worker for every request. On deny it
// is the structured refusal of requirement A-4: a code and a rule, no prose.
type response struct {
	Verdict    string          `json:"verdict"`               // allow | deny | approve
	ReasonCode string          `json:"reason_code,omitempty"` // machine-readable, on deny/approve
	Rule       string          `json:"rule,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"` // tool output, on allow
}

// governor holds everything the request loop needs.
type governor struct {
	man     *manifest.Manifest
	schemas map[string]*schema.Schema // compiled per tool at startup
	tasks   *taskstate.Store
	log     *audit.Writer
	user    string // originating_user for every audit record
	dryRun  bool
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "signed manifest (JSON); its .sig must sit beside it")
	pubkeyPath := fs.String("pubkey", "", "hex Ed25519 public key that signed the manifest")
	auditPath := fs.String("audit", "", "audit chain to append to")
	workerUID := fs.Int("worker-uid", -1, "UID the worker is expected to run as (default: this process's UID)")
	workerUser := fs.String("worker-user", "", "run the worker AS this user (requires agentd to start as root); implies -worker-uid")
	dryRun := fs.Bool("dry-run", false, "log verdicts but execute anyway (P-5)")
	killDir := fs.String("kill-dir", "", "directory to watch; any file appearing there stops the worker (G-6)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	workerCmd := fs.Args()
	if *manifestPath == "" || *pubkeyPath == "" || *auditPath == "" || len(workerCmd) == 0 {
		return fmt.Errorf("run: -manifest, -pubkey, -audit and a worker command after -- are all required")
	}

	// --- G-1: nothing happens until the manifest verifies. ---
	pub, err := manifest.LoadPublicKey(*pubkeyPath)
	if err != nil {
		return err
	}
	man, err := manifest.Load(*manifestPath, pub)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}

	// Compile every tool's args schema now, so a bad schema fails at startup
	// rather than on the first request that happens to use it.
	schemas := make(map[string]*schema.Schema, len(man.Tools))
	for _, t := range man.Tools {
		sc, err := schema.Compile(t.ArgsSchema)
		if err != nil {
			return fmt.Errorf("refusing to start: tool %q: %w", t.Name, err)
		}
		schemas[t.Name] = sc
	}

	uid := uint32(os.Getuid())
	if *workerUID >= 0 {
		uid = uint32(*workerUID)
	}

	// -worker-user: look the account up and, if we are root, drop the worker
	// to it. This is the week-1 stand-in for the week-4 container sandbox: it
	// gives SO_PEERCRED something real to check (G-3) because the worker's UID
	// now differs from the governor's.
	var cred *syscall.Credential
	if *workerUser != "" {
		u, err := user.Lookup(*workerUser)
		if err != nil {
			return fmt.Errorf("run: -worker-user: %w", err)
		}
		wuid, _ := strconv.Atoi(u.Uid)
		wgid, _ := strconv.Atoi(u.Gid)
		if os.Getuid() != 0 {
			return fmt.Errorf("run: -worker-user requires agentd to be started as root (to drop privileges for the worker)")
		}
		if wuid == 0 {
			return fmt.Errorf("run: refusing to run the worker as root")
		}
		uid = uint32(wuid)
		cred = &syscall.Credential{Uid: uint32(wuid), Gid: uint32(wgid), NoSetGroups: true}
	}
	if os.Getuid() == 0 && cred == nil {
		fmt.Fprintln(os.Stderr, "agentd: WARNING: running as root with the worker also as root; use -worker-user for a real boundary")
	}

	// Who launched the governor. This is originating_user on every record (A-5).
	me := "uid:" + strconv.Itoa(os.Getuid())
	if u, err := user.Current(); err == nil && u.Username != "" {
		me = u.Username
	}

	log, err := audit.Open(*auditPath, 50*time.Millisecond)
	if err != nil {
		return err
	}
	defer log.Close()

	g := &governor{man: man, schemas: schemas, tasks: taskstate.New(), log: log, user: me, dryRun: *dryRun}

	g.record(audit.Record{Event: "start", Detail: fmt.Sprintf("manifest=%s worker_uid=%d dry_run=%v", filepath.Base(*manifestPath), uid, *dryRun)})

	// --- G-2: spawn the worker with its end of the socketpair on fd 3. ---
	cmd := exec.Command(workerCmd[0], workerCmd[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = minimalEnv()
	// Own process group so the kill switch can take down the worker and
	// everything it forked in one signal.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: cred}

	pair, err := socket.Spawn(cmd, uid, schema.MaxFrameBytes)
	if err != nil {
		g.record(audit.Record{Event: "stop", Detail: "worker failed to start: " + err.Error()})
		return err
	}
	defer pair.Close()

	// --- G-6: kill switch on its own goroutine, independent of the request loop. ---
	killed := make(chan string, 1)
	go killSwitch(*killDir, killed)

	// The request loop runs in its own goroutine so the main goroutine can
	// select between "loop finished" and "kill switch fired".
	loopDone := make(chan error, 1)
	go func() { loopDone <- g.serve(pair) }()

	select {
	case why := <-killed:
		// Kill the whole process group. Negative pid = group.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		g.record(audit.Record{Event: "kill", Detail: why})
		<-loopDone // the loop sees EOF once the worker is dead
	case err = <-loopDone:
		if err != nil {
			// The loop stopped on a fatal error (an unauthenticated sender,
			// most likely). The worker may be blocked waiting for a reply
			// that will never come, so take the whole group down before
			// Wait() or we deadlock.
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			g.record(audit.Record{Event: "stop", Detail: "request loop error, worker killed: " + err.Error()})
		}
	}

	waitErr := cmd.Wait()
	code := 0
	if ee, ok := waitErr.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	g.record(audit.Record{Event: "stop", Detail: "worker exited", ExitCode: &code})
	return nil
}

// serve is the request loop: read a frame, decide, respond, record. One
// request at a time; the PoC worker is a single agent.
func (g *governor) serve(pair *socket.Pair) error {
	for {
		raw, err := pair.ReadFrame()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// A peer-credential failure is the attack case of G-3. Record it
			// with the error and stop; we do not keep talking to an
			// unauthenticated peer.
			g.record(audit.Record{Event: "reject", Detail: err.Error(), ReasonCode: "socket_auth"})
			if errors.Is(err, socket.ErrPeerUID) || errors.Is(err, socket.ErrOverflowUID) {
				return err
			}
			// Malformed framing: tell the worker and keep going.
			_ = pair.WriteFrame(mustJSON(response{Verdict: "deny", ReasonCode: "bad_frame"}))
			continue
		}

		resp := g.handle(raw)
		if err := pair.WriteFrame(mustJSON(resp)); err != nil {
			return err
		}
	}
}

// handle is the whole decision path for one request, in order:
// schema (G-4) -> policy (P-2/P-3) -> execute -> audit (A-2).
func (g *governor) handle(raw []byte) response {
	// G-4: the frame must be exactly {tool, args, task_id, justification}.
	req, err := schema.ParseRequest(raw)
	if err != nil {
		g.record(audit.Record{Event: "reject", Detail: err.Error(), ReasonCode: "schema"})
		return response{Verdict: "deny", ReasonCode: "schema_invalid"}
	}

	// Hash the args once. Policy sees the hash; the audit record carries the
	// hash; week 3's Biscuit binds to the hash. The args themselves go only to
	// the schema validator and, later, the executor.
	sum := sha256.Sum256(canonical(req.Args))
	argsHash := hex.EncodeToString(sum[:])

	tool := g.man.Tool(req.Tool)
	if tool != nil {
		// Validate args against this tool's schema before policy runs.
		if err := g.schemas[tool.Name].Validate(req.Args); err != nil {
			g.record(audit.Record{Event: "reject", TaskID: req.TaskID, Tool: req.Tool, Detail: err.Error(), ReasonCode: "schema", ArgsHash: argsHash})
			return response{Verdict: "deny", ReasonCode: "args_invalid"}
		}
	}

	// Build the policy input from the manifest and task store. Note what is
	// absent: req.Justification is never read.
	_, depth := g.tasks.Delegation(req.TaskID)
	taint := g.tasks.TaintHWM(req.TaskID)
	in := policy.Input{
		Role:               g.man.Role,
		MaxDelegationDepth: g.man.MaxDelegationDepth,
		ToolKnown:          tool != nil,
		ToolName:           req.Tool,
		CallCount:          g.tasks.Count(req.TaskID, req.Tool),
		TaintHWM:           taint,
		DelegationDepth:    depth,
		ArgsHash:           argsHash,
	}
	if tool != nil {
		in.ToolKind = tool.Kind
		in.ToolDirection = tool.Direction
		in.SensitivityFloor = tool.SensitivityFloor
		in.MaxCallsPerTask = tool.MaxCallsPerTask
	}
	d := policy.Decide(in)

	g.record(audit.Record{
		Event: "verdict", TaskID: req.TaskID, Tool: req.Tool,
		Verdict: string(d.Verdict), RuleFired: d.Rule, ReasonCode: d.ReasonCode,
		TaintHWM: &taint, ArgsHash: argsHash, DryRun: g.dryRun,
	})

	switch d.Verdict {
	case policy.Deny:
		if !g.dryRun {
			return response{Verdict: "deny", ReasonCode: d.ReasonCode, Rule: d.Rule}
		}
		// P-5: dry-run logs the deny and falls through to execute.
	case policy.Approve:
		// Week 3 adds the CLI approval gate. Until then, approve is reported
		// to the worker as pending and nothing executes.
		if !g.dryRun {
			return response{Verdict: "approve", ReasonCode: d.ReasonCode, Rule: d.Rule}
		}
	}

	// Allowed (or dry-run). Count it, then run it.
	g.tasks.RecordAllow(req.TaskID, req.Tool)
	result, exit := g.execute(req)
	g.record(audit.Record{Event: "executor", TaskID: req.TaskID, Tool: req.Tool, ArgsHash: argsHash, ExitCode: &exit, Detail: "stub"})
	return response{Verdict: "allow", Result: result}
}

// execute is the week-1 stand-in for real executors (week 3). It echoes the
// args back so the end-to-end path can be demonstrated. It is the only place
// in the governor that will ever hand args onward, and in week 3 it becomes
// "spawn executor with Biscuit + credential on stdin".
func (g *governor) execute(req *schema.Request) (json.RawMessage, int) {
	out := map[string]any{"stub": true, "tool": req.Tool, "echo": req.Args}
	return mustJSON(out), 0
}

// record appends to the audit chain, filling the identity fields. Failures to
// write audit are fatal to the governor: a decision that cannot be recorded
// must not stand.
func (g *governor) record(r audit.Record) {
	r.OriginatingUser = g.user
	r.AgentRole = g.man.Role
	if _, err := g.log.Append(r); err != nil {
		fmt.Fprintf(os.Stderr, "agentd: audit write failed, stopping: %v\n", err)
		os.Exit(3)
	}
}

// killSwitch fires on SIGUSR1 or when any file appears in dir (G-6). It polls
// the directory every 50 ms, which keeps the 100 ms budget with margin and
// avoids an inotify dependency.
func killSwitch(dir string, out chan<- string) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGINT, syscall.SIGTERM)

	var tick <-chan time.Time
	if dir != "" {
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case s := <-sig:
			out <- "signal " + s.String()
			return
		case <-tick:
			entries, err := os.ReadDir(dir)
			if err == nil && len(entries) > 0 {
				out <- "kill file " + entries[0].Name()
				return
			}
		}
	}
}

// minimalEnv is what the worker gets: a PATH and nothing of ours. No Vault
// address, no API keys, no proxy settings. The worker learns about the world
// only through tool results. Week 4 moves this into the container spec.
func minimalEnv() []string {
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"PERIMETER_FD=" + strconv.Itoa(socket.WorkerFD),
		"PYTHONUNBUFFERED=1",
	}
}

// canonical re-encodes JSON with sorted keys and no whitespace so that the
// same logical args always hash the same. encoding/json sorts map keys.
func canonical(raw json.RawMessage) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only reachable on a programming error
	}
	return b
}

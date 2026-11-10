package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
	"strings"
	"syscall"
	"time"

	"github.com/therealnoof/agent-perimeter/internal/approval"
	"github.com/therealnoof/agent-perimeter/internal/audit"
	"github.com/therealnoof/agent-perimeter/internal/canon"
	"github.com/therealnoof/agent-perimeter/internal/manifest"
	"github.com/therealnoof/agent-perimeter/internal/policy"
	"github.com/therealnoof/agent-perimeter/internal/schema"
	"github.com/therealnoof/agent-perimeter/internal/socket"
	"github.com/therealnoof/agent-perimeter/internal/taskstate"
	"github.com/therealnoof/agent-perimeter/internal/tokens"
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
	engine  *policy.Engine            // signed Cedar policies, loaded at startup
	minter  *tokens.Minter            // per-call token signer (C-1)
	approve approval.Approver         // human gate for "approve" verdicts (A-3)
	tasks   *taskstate.Store
	log     *audit.Writer
	user    string // originating_user for every audit record
	dryRun  bool

	// How to run a tool: the executor binary and what it needs to know.
	executorBin string
	govPubPath  string
	secretsSock string
	mockAddr    string
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "signed manifest (JSON); its .sig must sit beside it")
	pubkeyPath := fs.String("pubkey", "", "hex Ed25519 public key that signed the manifest")
	auditPath := fs.String("audit", "", "audit chain to append to")
	policyDir := fs.String("policies", "policies", "directory of signed *.cedar policy files")
	workerUID := fs.Int("worker-uid", -1, "UID the worker is expected to run as (default: this process's UID)")
	workerUser := fs.String("worker-user", "", "run the worker AS this user (requires agentd to start as root); implies -worker-uid")
	dryRun := fs.Bool("dry-run", false, "log verdicts but execute anyway (P-5)")
	killDir := fs.String("kill-dir", "", "directory to watch; any file appearing there stops the worker (G-6)")
	govKey := fs.String("gov-key", "", "governor token-signing private key (hex); generate with 'agentd keygen'")
	govPubOut := fs.String("gov-pub-out", "run/governor.pub", "where to write the governor public key for executors and secretsd")
	executorBin := fs.String("executor", "bin/executor", "executor binary spawned per allowed call")
	secretsSock := fs.String("secrets-sock", "", "secretsd socket passed to executors (empty: tools with secrets will fail)")
	mockAddr := fs.String("mock-addr", "127.0.0.1:9811", "mock service address passed to executors")
	approver := fs.String("approver", "cli", "who answers approve verdicts: cli | deny | allow-all-UNSAFE-tests-only")
	approvalTimeout := fs.Duration("approval-timeout", approval.DefaultTimeout, "how long a CLI prompt waits before deny")
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

	// --- P-1: policies are signed with the same key and verified the same way. ---
	engine, err := policy.Load(*policyDir, pub)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}

	// --- C-1: the governor's own token-signing key. ---
	// Generated once with `agentd keygen` and kept on disk mode 0600, so the
	// sidecar can be started with the public half before the governor runs.
	if *govKey == "" {
		return fmt.Errorf("run: -gov-key is required (run 'agentd keygen -out run/governor.key' once)")
	}
	govPriv, err := loadGovKey(*govKey)
	if err != nil {
		return err
	}
	govPub := govPriv.Public().(ed25519.PublicKey)
	if err := os.MkdirAll(filepath.Dir(*govPubOut), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*govPubOut, []byte(hex.EncodeToString(govPub)+"\n"), 0o644); err != nil {
		return fmt.Errorf("run: write governor public key: %w", err)
	}

	// --- A-3: who answers "approve". ---
	var appr approval.Approver
	switch *approver {
	case "cli":
		appr = approval.NewCLI(*approvalTimeout)
	case "deny":
		appr = approval.DenyAll{}
	case "allow-all-UNSAFE-tests-only":
		fmt.Fprintln(os.Stderr, "agentd: WARNING: every approve verdict will be auto-approved; this mode is for tests only")
		appr = approval.AllowAll{Who: "auto"}
	default:
		return fmt.Errorf("run: -approver must be cli, deny, or allow-all-UNSAFE-tests-only")
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

	g := &governor{
		man: man, schemas: schemas, engine: engine, tasks: taskstate.New(), log: log, user: me, dryRun: *dryRun,
		minter: tokens.NewMinter(govPriv, 0), approve: appr,
		executorBin: *executorBin, govPubPath: *govPubOut, secretsSock: *secretsSock, mockAddr: *mockAddr,
	}

	// Identity fingerprint of the worker we are about to start: the resolved
	// executable and, if the first argument is a file, that file. Recorded,
	// never decided on. A changed hash between runs is the operator's cue
	// that the agent code changed.
	exeHash, scriptHash := fingerprintWorker(workerCmd)
	g.record(audit.Record{
		Event: "start",
		Detail: fmt.Sprintf("manifest=%s policies=%s worker_uid=%d dry_run=%v governor=%s approver=%s",
			filepath.Base(*manifestPath), strings.Join(engine.Files(), ","), uid, *dryRun, tokens.Fingerprint(govPub)[:12], *approver),
		WorkerCmd: strings.Join(workerCmd, " "), WorkerExeSHA256: exeHash, WorkerScriptSHA256: scriptHash,
	})

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
	t0 := time.Now()
	reqID := newReqID()
	// Every record this request produces carries reqID and the stage timings
	// known so far, so a reader can rebuild the span tree from the chain.
	var tSchema, tPolicy, tApproval, tExec time.Duration
	target := ""
	jlen := 0
	stamp := func(r audit.Record) audit.Record {
		r.ReqID = reqID
		if r.Target == "" {
			r.Target = target
		}
		r.JustificationLen = jlen
		r.SchemaUS, r.PolicyUS = tSchema.Microseconds(), tPolicy.Microseconds()
		r.ApprovalMS, r.ExecMS = tApproval.Milliseconds(), tExec.Milliseconds()
		r.TotalUS = time.Since(t0).Microseconds()
		return r
	}

	// G-4: the frame must be exactly {tool, args, task_id, justification[, client]}.
	req, err := schema.ParseRequest(raw)
	if err != nil {
		tSchema = time.Since(t0)
		g.record(stamp(audit.Record{Event: "reject", Detail: err.Error(), ReasonCode: "schema"}))
		return response{Verdict: "deny", ReasonCode: "schema_invalid"}
	}

	jlen = len(req.Justification)

	// Hash the args once. Policy sees the hash; the audit record carries the
	// hash; week 3's Biscuit binds to the hash. The args themselves go only to
	// the schema validator and, later, the executor.
	argsHash := canon.Hash(req.Args)

	tool := g.man.Tool(req.Tool)
	if tool != nil {
		// Validate args against this tool's schema before policy runs.
		if err := g.schemas[tool.Name].Validate(req.Args); err != nil {
			tSchema = time.Since(t0)
			g.record(stamp(audit.Record{Event: "reject", TaskID: req.TaskID, Tool: req.Tool, Client: req.Client, Detail: err.Error(), ReasonCode: "schema", ArgsHash: argsHash}))
			return response{Verdict: "deny", ReasonCode: "args_invalid"}
		}
	}
	tSchema = time.Since(t0)

	// Build the policy input from the manifest and task store. Note what is
	// absent: req.Justification is never read, and req.Args contributes only
	// its hash and (if the tool declares one) its bounded resource argument.
	_, depth := g.tasks.Delegation(req.TaskID)
	taint := g.tasks.TaintHWM(req.TaskID)
	in := policy.Input{
		Role:               g.man.Role,
		DataClearance:      g.man.DataClearance,
		MaxDelegationDepth: g.man.MaxDelegationDepth,
		ToolKnown:          tool != nil,
		ToolName:           req.Tool,
		Target:             policy.NoTarget,
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
		if tool.ResourceArg != "" {
			// Safe to read: the manifest loader proved this field is an
			// enum- or pattern-bounded string, and the schema validator just
			// proved this value satisfies it.
			in.Target = canon.StringField(req.Args, tool.ResourceArg)
		}
	}
	target = in.Target
	tp := time.Now()
	d := g.engine.Decide(in)
	tPolicy = time.Since(tp)

	g.record(stamp(audit.Record{
		Event: "verdict", TaskID: req.TaskID, Tool: req.Tool, Client: req.Client,
		Verdict: string(d.Verdict), RuleFired: d.Rule, ReasonCode: d.ReasonCode,
		TaintHWM: &taint, ArgsHash: argsHash, DryRun: g.dryRun,
	}))

	approverID := ""
	switch d.Verdict {
	case policy.Deny:
		if !g.dryRun {
			return response{Verdict: "deny", ReasonCode: d.ReasonCode, Rule: d.Rule}
		}
		// P-5: dry-run logs the deny and falls through to execute.
	case policy.Approve:
		if g.dryRun {
			break
		}
		// A-3: a human sees structural facts and decides. The agent's
		// justification is carried but hidden until asked for.
		ta := time.Now()
		out := g.approve.Ask(approval.Prompt{
			TaskID: req.TaskID, Tool: req.Tool, Target: in.Target, TaintHWM: taint,
			Rule: d.Rule, ArgsHash: argsHash, Justification: req.Justification,
		})
		tApproval = time.Since(ta)
		g.record(stamp(audit.Record{
			Event: "approval", TaskID: req.TaskID, Tool: req.Tool, ArgsHash: argsHash,
			ApproverID: out.ApproverID, ReasonCode: out.ReasonCode, RuleFired: d.Rule,
			Verdict: map[bool]string{true: "approved", false: "declined"}[out.Approved],
		}))
		if !out.Approved {
			return response{Verdict: "deny", ReasonCode: out.ReasonCode, Rule: d.Rule}
		}
		approverID = out.ApproverID
	}

	// Allowed (or approved, or dry-run). Count it, run it, then raise taint
	// by what the tool's SOURCE is declared to return (D-2). The content is
	// never inspected; a confidential ticket read is confidential whether or
	// not the agent later reformats it.
	g.tasks.RecordAllow(req.TaskID, req.Tool)
	te := time.Now()
	result, jti, exit, detail := g.execute(req, tool, in.Target, argsHash)
	tExec = time.Since(te)
	newTaint := taint
	if tool != nil && exit == 0 {
		// D-2: taint rises to the higher of the manifest's floor for this
		// source and what the executor learned from the source system's own
		// classification. The executor is on the trusted side (it verified
		// our token and we spawned it); the worker never gets a say.
		level := tool.ResultSensitivity
		if reported := reportedSensitivity(result); reported > level {
			level = reported
		}
		if level > 0 {
			newTaint = g.tasks.RaiseTaint(req.TaskID, level)
		}
	}
	g.record(stamp(audit.Record{
		Event: "executor", TaskID: req.TaskID, Tool: req.Tool, ArgsHash: argsHash,
		TokenID: jti, ExitCode: &exit, TaintHWM: &newTaint, ApproverID: approverID, Detail: detail,
	}))
	if exit != 0 {
		return response{Verdict: "deny", ReasonCode: "executor_failed", Rule: d.Rule}
	}
	return response{Verdict: "allow", Result: result}
}

// execute mints a per-call token and runs the tool in a fresh executor
// process (E-1). The token binds tool, target and args hash and lives five
// seconds; the executor verifies it offline before doing anything (C-2).
// The governor never sees a credential: the executor fetches its own from
// the sidecar, presenting the same token.
//
// Returns the executor's stdout (the result), the token id, the exit code,
// and a one-line detail for the audit record. Exit codes: 0 ok, 2 token
// rejected, 3 credential refused, 4 tool failed, 1 internal.
func (g *governor) execute(req *schema.Request, tool *manifest.Tool, target, argsHash string) (json.RawMessage, string, int, string) {
	if tool == nil {
		// Only reachable in dry-run for an unknown tool.
		return nil, "", 1, "no such tool"
	}
	tok, jti, err := g.minter.Mint(req.Tool, target, argsHash, req.TaskID)
	if err != nil {
		return nil, "", 1, "mint: " + err.Error()
	}

	job, _ := json.Marshal(map[string]any{
		"token": tok, "tool": req.Tool, "target": target, "args": req.Args,
	})
	args := []string{"-family", tool.Executor, "-gov-pub", g.govPubPath, "-mock-addr", g.mockAddr}
	if g.secretsSock != "" {
		args = append(args, "-secrets-sock", g.secretsSock)
	}
	cmd := exec.Command(g.executorBin, args...)
	cmd.Stdin = bytes.NewReader(job)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"} // nothing of ours

	err = cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		return nil, jti, 1, "spawn: " + err.Error()
	}
	detail := strings.TrimSpace(stderr.String())
	if detail == "" {
		detail = tool.Executor
	}
	if code != 0 {
		return nil, jti, code, detail
	}
	return json.RawMessage(bytes.TrimSpace(stdout.Bytes())), jti, 0, detail
}

// newReqID returns 8 random bytes as hex: the span id for one request.
func newReqID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b[:])
}

// fingerprintWorker hashes the worker's resolved executable and, when the
// first argument names a readable file (a script), that file too. Empty
// strings when a hash cannot be taken; never fatal.
func fingerprintWorker(cmd []string) (exeHash, scriptHash string) {
	if len(cmd) == 0 {
		return "", ""
	}
	if path, err := exec.LookPath(cmd[0]); err == nil {
		exeHash = fileSHA256(path)
	}
	if len(cmd) > 1 {
		if st, err := os.Stat(cmd[1]); err == nil && st.Mode().IsRegular() {
			scriptHash = fileSHA256(cmd[1])
		}
	}
	return
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// reportedSensitivity reads the executor's "sensitivity" field, clamped 0-10.
func reportedSensitivity(result json.RawMessage) int {
	var env struct {
		Sensitivity int `json:"sensitivity"`
	}
	if json.Unmarshal(result, &env) != nil {
		return 0
	}
	if env.Sensitivity < 0 {
		return 0
	}
	if env.Sensitivity > 10 {
		return 10
	}
	return env.Sensitivity
}

// loadGovKey reads the governor's hex Ed25519 private key.
func loadGovKey(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("run: governor key: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("run: governor key %s is readable by others (mode %o); chmod 600 it", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("run: governor key is not a valid Ed25519 private key")
	}
	return ed25519.PrivateKey(key), nil
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

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only reachable on a programming error
	}
	return b
}

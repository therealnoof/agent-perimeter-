// Command executor runs exactly one tool call, then exits. The governor
// spawns one per allowed call. Requirements C-2, E-1.
//
//	executor -family jira -gov-pub run/governor.pub [-secrets-sock PATH] [-mock-addr HOST:PORT]
//
// stdin:  one JSON object {"token", "tool", "target", "args"}
// stdout: {"ok", "tool", "jti", "result", "sensitivity"?} — sensitivity is
//
//	the source system's own classification of the result (0-10) when
//	the family can tell; the governor raises task taint to it
//
// stderr: diagnostics
// exit:   0 ok · 2 token rejected · 3 credential refused · 4 tool failed · 1 other
//
// Before doing anything the executor verifies the governor's token offline:
// signature against the governor public key, time window, and that the
// token's tool/target/args_hash equal what it was asked to run. It
// recomputes the args hash itself from the bytes it received; it does not
// trust a hash handed to it. A token that does not check out is exit 2 and
// nothing runs. This is defense in depth (C-2): the governor already
// decided, but a compromised governor or a forged request still cannot make
// an executor act without a key it does not have.
//
// If the tool needs a credential, the executor asks the secrets sidecar,
// presenting the same token. The credential lives in this process's memory
// for the duration of one call and is gone when it exits (E-1).
//
// Families are the only code that knows how to talk to a service. Adding a
// tool family is adding a case here; the governor does not change.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/therealnoof/agent-perimeter/internal/canon"
	"github.com/therealnoof/agent-perimeter/internal/tokens"
)

const (
	exitOK       = 0
	exitToken    = 2
	exitCred     = 3
	exitTool     = 4
	exitInternal = 1
)

// job is what the governor writes to stdin.
type job struct {
	Token  string          `json:"token"`
	Tool   string          `json:"tool"`
	Target string          `json:"target"`
	Args   json.RawMessage `json:"args"`
}

func main() {
	family := flag.String("family", "", "tool family: echo | jira | slack")
	govPub := flag.String("gov-pub", "", "governor public key file (hex Ed25519)")
	secretsSock := flag.String("secrets-sock", "", "secrets sidecar socket; required for tools with a secret")
	mockAddr := flag.String("mock-addr", "127.0.0.1:9811", "mock service address for jira/slack families")
	flag.Parse()
	os.Exit(run(*family, *govPub, *secretsSock, *mockAddr))
}

func run(family, govPub, secretsSock, mockAddr string) int {
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "executor: "+format+"\n", a...)
		return code
	}

	// --- read the job ---
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return fail(exitInternal, "read stdin: %v", err)
	}
	var j job
	if err := json.Unmarshal(raw, &j); err != nil || j.Token == "" || j.Tool == "" {
		return fail(exitInternal, "malformed job")
	}

	// --- C-2: verify the token against the governor key, offline ---
	pub, err := loadPub(govPub)
	if err != nil {
		return fail(exitInternal, "%v", err)
	}
	v := tokens.NewVerifier(pub)
	claims, err := v.Verify(j.Token, j.Tool, j.Target, canon.Hash(j.Args))
	if err != nil {
		return fail(exitToken, "token rejected: %v", err)
	}

	// --- credential, if this tool has one ---
	var secret map[string]any
	if secretsSock != "" {
		secret, err = fetchSecret(secretsSock, j.Token, j.Tool)
		if err != nil {
			// "no secret for tool" is fine: the tool simply has none.
			if !strings.Contains(err.Error(), "no secret for tool") {
				return fail(exitCred, "credential refused: %v", err)
			}
		}
	}

	// --- do the work ---
	var result any
	switch family {
	case "echo":
		result, err = runEcho(j)
	case "jira":
		result, err = runJira(j, secret, mockAddr)
	case "slack":
		result, err = runSlack(j, secret, mockAddr)
	default:
		return fail(exitInternal, "unknown family %q", family)
	}
	if err != nil {
		return fail(exitTool, "%s: %v", j.Tool, err)
	}

	out := map[string]any{"ok": true, "tool": j.Tool, "jti": claims.JTI, "result": result}
	if sensitivity > 0 {
		out["sensitivity"] = sensitivity
	}
	json.NewEncoder(os.Stdout).Encode(out)
	return exitOK
}

// fetchSecret asks the sidecar for this tool's credential, presenting the
// governor token. The sidecar verifies the token itself; we never see or
// hold anything but the one secret we are entitled to.
func fetchSecret(sock, token, tool string) (map[string]any, error) {
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("sidecar: %w", err)
	}
	defer conn.Close()
	req, _ := json.Marshal(map[string]string{"token": token, "tool": tool})
	if _, err := conn.Write(append(req, '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, fmt.Errorf("sidecar: %w", err)
	}
	var resp struct {
		OK     bool           `json:"ok"`
		Secret map[string]any `json:"secret"`
		Error  string         `json:"error"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, errors.New("sidecar: malformed reply")
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	return resp.Secret, nil
}

func loadPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("governor public key: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("governor public key is not a valid Ed25519 key")
	}
	return ed25519.PublicKey(key), nil
}

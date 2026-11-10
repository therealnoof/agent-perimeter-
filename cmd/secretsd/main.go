// Command secretsd is the credential sidecar. It is the only process that
// holds a secrets-backend credential, and it releases a secret to exactly
// one caller: an executor presenting a valid, unexpired, never-before-seen
// governor token whose tool maps to that secret in the signed manifest.
//
//	secretsd -listen /run/agent-perimeter/secrets.sock \
//	         -gov-pub run/governor.pub -manifest M.json -pubkey K.pub \
//	         [-secrets-file secrets.json | -vault-addr URL -vault-role-id ID (secret id from VAULT_SECRET_ID)]
//
// Why a separate process (the trust argument, in one paragraph): the
// governor decides; it does not need secrets to decide. If the governor
// held a Vault token, a compromised governor could harvest every credential
// its policy allowed. With the sidecar, the governor can at worst authorise
// a call it should not have, and the executor for that call gets one
// credential, once. Secrets never pass through the governor's memory.
//
// Protocol on the socket: one JSON line in, one JSON line out.
//
//	→ {"token": "<governor token>", "tool": "jira_update"}
//	← {"ok": true, "secret": {...}}        or
//	← {"ok": false, "error": "token: expired"}
//
// Trust: the socket is created mode 0600 under the operator's uid, so only
// processes the operator started can connect. Week 4 moves executors to
// their own uid/group and the socket to 0660 with that group.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/therealnoof/agent-perimeter/internal/manifest"
	"github.com/therealnoof/agent-perimeter/internal/tokens"
)

// Backend fetches a secret by path.
type Backend interface {
	Get(path string) (map[string]any, error)
}

func main() {
	listen := flag.String("listen", "", "unix socket path to serve on")
	govPub := flag.String("gov-pub", "", "file with the governor's hex Ed25519 public key (written by agentd)")
	manifestPath := flag.String("manifest", "", "signed manifest; its tools' secret_path values are the only secrets ever released")
	pubkeyPath := flag.String("pubkey", "", "operator public key that signed the manifest")
	secretsFile := flag.String("secrets-file", "", "file backend: JSON object of path -> secret object")
	vaultAddr := flag.String("vault-addr", "", "vault backend: address, e.g. http://127.0.0.1:8200")
	vaultRole := flag.String("vault-role-id", "", "vault backend: AppRole role id (secret id from VAULT_SECRET_ID env)")
	vaultMount := flag.String("vault-mount", "secret", "vault backend: KV v2 mount")
	flag.Parse()

	if *listen == "" || *govPub == "" || *manifestPath == "" || *pubkeyPath == "" {
		log.Fatal("secretsd: -listen, -gov-pub, -manifest and -pubkey are required")
	}

	// The manifest is the allow-list of (tool -> secret path). Verified with
	// the operator key exactly as agentd does, so the sidecar and the
	// governor agree on what exists.
	opPub, err := manifest.LoadPublicKey(*pubkeyPath)
	if err != nil {
		log.Fatalf("secretsd: %v", err)
	}
	man, err := manifest.Load(*manifestPath, opPub)
	if err != nil {
		log.Fatalf("secretsd: refusing to start: %v", err)
	}
	paths := map[string]string{} // tool -> secret path
	for _, t := range man.Tools {
		if t.SecretPath != "" {
			paths[t.Name] = t.SecretPath
		}
	}

	gov, err := loadGovPub(*govPub)
	if err != nil {
		log.Fatalf("secretsd: %v", err)
	}
	verifier := tokens.NewVerifier(gov)

	var backend Backend
	switch {
	case *secretsFile != "":
		backend, err = newFileBackend(*secretsFile)
	case *vaultAddr != "":
		backend, err = newVaultBackend(*vaultAddr, *vaultMount, *vaultRole, os.Getenv("VAULT_SECRET_ID"))
	default:
		err = errors.New("one of -secrets-file or -vault-addr is required")
	}
	if err != nil {
		log.Fatalf("secretsd: %v", err)
	}

	os.Remove(*listen)
	ln, err := net.Listen("unix", *listen)
	if err != nil {
		log.Fatalf("secretsd: listen: %v", err)
	}
	if err := os.Chmod(*listen, 0o600); err != nil {
		log.Fatalf("secretsd: chmod socket: %v", err)
	}
	defer ln.Close()
	log.Printf("secretsd: serving %d tool->secret mappings on %s, governor %s", len(paths), *listen, tokens.Fingerprint(gov)[:12])

	var mu sync.Mutex // serialise; volume is one request per tool call
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("secretsd: accept: %v", err)
			continue
		}
		go func() {
			defer conn.Close()
			mu.Lock()
			defer mu.Unlock()
			handle(conn, verifier, paths, backend)
		}()
	}
}

type request struct {
	Token string `json:"token"`
	Tool  string `json:"tool"`
}

type response struct {
	OK     bool           `json:"ok"`
	Secret map[string]any `json:"secret,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// handle serves one request. Every refusal is logged with the token's
// claims if they parse, so an operator can see what was attempted.
func handle(conn net.Conn, v *tokens.Verifier, paths map[string]string, b Backend) {
	reply := func(r response) {
		json.NewEncoder(conn).Encode(r)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		reply(response{Error: "empty request"})
		return
	}
	var req request
	if err := json.Unmarshal(line, &req); err != nil || req.Token == "" || req.Tool == "" {
		reply(response{Error: "malformed request"})
		return
	}

	path, ok := paths[req.Tool]
	if !ok {
		log.Printf("secretsd: REFUSED tool=%s: no secret mapped", req.Tool)
		reply(response{Error: "no secret for tool"})
		return
	}

	// Verify the token's signature, window and single use. We bind on tool
	// only: the sidecar does not know the args, and does not need to; the
	// executor checks the args hash. Target and hash are taken from the
	// token itself so Verify's binding check passes on those.
	c, err := v.Parse(req.Token)
	if err != nil {
		log.Printf("secretsd: REFUSED tool=%s: %v", req.Tool, err)
		reply(response{Error: err.Error()})
		return
	}
	if _, err := v.Verify(req.Token, c.Tool, c.Target, c.ArgsHash); err != nil {
		log.Printf("secretsd: REFUSED tool=%s jti=%s: %v", req.Tool, c.JTI, err)
		reply(response{Error: err.Error()})
		return
	}
	if c.Tool != req.Tool {
		log.Printf("secretsd: REFUSED tool=%s jti=%s: token is for %s", req.Tool, c.JTI, c.Tool)
		reply(response{Error: "token is for a different tool"})
		return
	}

	secret, err := b.Get(path)
	if err != nil {
		log.Printf("secretsd: backend error tool=%s path=%s: %v", req.Tool, path, err)
		reply(response{Error: "backend: " + err.Error()})
		return
	}
	log.Printf("secretsd: RELEASED tool=%s task=%s jti=%s path=%s", req.Tool, c.TaskID, c.JTI[:8], path)
	reply(response{OK: true, Secret: secret})
}

func loadGovPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read governor public key: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("governor public key is not a valid Ed25519 key")
	}
	return ed25519.PublicKey(key), nil
}

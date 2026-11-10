// Command egress-proxy is the only way out of an executor sandbox.
// Requirement E-4, redesigned: executors have NO network interfaces. This
// proxy listens on a Unix socket that is bind-mounted into the sandbox; an
// executor dials it, sends an HTTP CONNECT carrying its per-call governor
// token, and the proxy makes the real TCP connection if, and only if:
//
//   - the token verifies against the governor's public key and is unexpired
//   - the requested host:port is in the manifest's egress_hosts list for the
//     token's tool
//
// Everything else is refused with 403 and a JSON log line naming the tool,
// task, token id and host, so a shell tool running `curl` inside the
// sandbox produces an audit trail rather than a connection.
//
// Why a Unix socket and not a network namespace with iptables REDIRECT, as
// the PRD first said: there is nothing to misconfigure. No routes, no
// nftables/iptables backend differences, no interface to probe. A sandbox
// with no interfaces and one socket file is a boundary a reviewer can see.
//
//	egress-proxy -listen run/egress.sock -gov-pub run/governor.pub -manifest M.json -pubkey K.pub
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
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/therealnoof/agent-perimeter/internal/manifest"
	"github.com/therealnoof/agent-perimeter/internal/tokens"
)

func main() {
	listen := flag.String("listen", "", "unix socket path to serve on")
	govPub := flag.String("gov-pub", "", "governor public key file")
	manifestPath := flag.String("manifest", "", "signed manifest; its tools' egress_hosts are the allow-list")
	pubkeyPath := flag.String("pubkey", "", "operator public key that signed the manifest")
	dialTimeout := flag.Duration("dial-timeout", 5*time.Second, "upstream connect timeout")
	flag.Parse()
	if *listen == "" || *govPub == "" || *manifestPath == "" || *pubkeyPath == "" {
		log.Fatal("egress-proxy: -listen, -gov-pub, -manifest and -pubkey are required")
	}

	opPub, err := manifest.LoadPublicKey(*pubkeyPath)
	if err != nil {
		log.Fatalf("egress-proxy: %v", err)
	}
	man, err := manifest.Load(*manifestPath, opPub)
	if err != nil {
		log.Fatalf("egress-proxy: refusing to start: %v", err)
	}
	allow := map[string]map[string]bool{} // tool -> host:port -> true
	for _, t := range man.Tools {
		if len(t.EgressHosts) > 0 {
			allow[t.Name] = map[string]bool{}
			for _, h := range t.EgressHosts {
				allow[t.Name][h] = true
			}
		}
	}

	gov, err := loadGovPub(*govPub)
	if err != nil {
		log.Fatalf("egress-proxy: %v", err)
	}
	v := tokens.NewVerifier(gov)

	os.Remove(*listen)
	ln, err := net.Listen("unix", *listen)
	if err != nil {
		log.Fatalf("egress-proxy: listen: %v", err)
	}
	os.Chmod(*listen, 0o600)
	defer ln.Close()
	logEvent("start", "", "", "", "", fmt.Sprintf("%d tools with egress", len(allow)))

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, v, allow, *dialTimeout)
	}
}

// handle serves one CONNECT. One connection = one upstream TCP stream.
func handle(c net.Conn, v *tokens.Verifier, allow map[string]map[string]bool, dialTimeout time.Duration) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})

	refuse := func(code int, why, tool, task, jti, host string) {
		logEvent("refused", tool, task, jti, host, why)
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\negress-proxy: %s\n", code, http.StatusText(code), why)
	}

	if req.Method != http.MethodConnect {
		refuse(405, "only CONNECT is served", "", "", "", req.Host)
		return
	}
	host := req.Host // CONNECT host:port
	if _, _, err := net.SplitHostPort(host); err != nil {
		refuse(400, "CONNECT target must be host:port", "", "", "", host)
		return
	}

	tok := strings.TrimPrefix(req.Header.Get("Proxy-Authorization"), "Bearer ")
	if tok == "" {
		refuse(407, "no governor token", "", "", "", host)
		return
	}
	// Signature and window only: a tool family may open more than one
	// connection per call, so the proxy does not enforce single use. The
	// sidecar and the executor's own check do.
	claims, err := v.Parse(tok)
	if err != nil {
		refuse(403, "token: "+err.Error(), "", "", "", host)
		return
	}
	if time.Now().After(time.Unix(claims.Expires, 0).Add(tokens.Skew)) {
		refuse(403, "token expired", claims.Tool, claims.TaskID, claims.JTI, host)
		return
	}
	if !allow[claims.Tool][host] {
		refuse(403, "host not in egress_hosts for tool", claims.Tool, claims.TaskID, claims.JTI, host)
		return
	}

	up, err := net.DialTimeout("tcp", host, dialTimeout)
	if err != nil {
		refuse(502, "upstream: "+err.Error(), claims.Tool, claims.TaskID, claims.JTI, host)
		return
	}
	defer up.Close()
	logEvent("connect", claims.Tool, claims.TaskID, claims.JTI, host, "")
	fmt.Fprint(c, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// Splice. Anything the reader already buffered goes upstream first.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(up, br); closeWrite(up) }()
	go func() { defer wg.Done(); io.Copy(c, up); closeWrite(c) }()
	wg.Wait()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

func logEvent(event, tool, task, jti, host, detail string) {
	rec := map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "event": event, "component": "egress-proxy"}
	for k, val := range map[string]string{"tool": tool, "task_id": task, "token_id": jti, "host": host, "detail": detail} {
		if val != "" {
			rec[k] = val
		}
	}
	b, _ := json.Marshal(rec)
	fmt.Fprintln(os.Stderr, string(b))
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

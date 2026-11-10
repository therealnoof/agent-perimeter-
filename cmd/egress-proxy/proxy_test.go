package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/therealnoof/agent-perimeter/internal/tokens"
)

// startProxy runs handle() on a temp Unix socket with a one-tool allow-list.
func startProxy(t *testing.T, v *tokens.Verifier, allow map[string]map[string]bool) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "egress.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c, v, allow, time.Second)
		}
	}()
	return sock
}

// connect sends one CONNECT and returns the status line and the connection.
func connect(t *testing.T, sock, hostport, token string) (int, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	auth := ""
	if token != "" {
		auth = "Proxy-Authorization: Bearer " + token + "\r\n"
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", hostport, hostport, auth)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, c, br
}

func TestProxy(t *testing.T) {
	pub, priv, _ := tokens.GenerateKey()
	minter := tokens.NewMinter(priv, 5*time.Second)
	v := tokens.NewVerifier(pub)

	// An upstream the allow-list permits for jira_read.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from upstream")
	}))
	defer up.Close()
	upHost := strings.TrimPrefix(up.URL, "http://")
	allow := map[string]map[string]bool{"jira_read": {upHost: true}}
	sock := startProxy(t, v, allow)

	tok, _, _ := minter.Mint("jira_read", "OPS-1", "h", "task-1")

	t.Run("allowed host is spliced through", func(t *testing.T) {
		code, c, br := connect(t, sock, upHost, tok)
		defer c.Close()
		if code != 200 {
			t.Fatalf("status %d", code)
		}
		fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upHost)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "hello from upstream" {
			t.Fatalf("body %q", body)
		}
	})

	t.Run("host not on tool's list is 403", func(t *testing.T) {
		code, c, _ := connect(t, sock, "127.0.0.1:1", tok)
		c.Close()
		if code != 403 {
			t.Fatalf("status %d", code)
		}
	})

	t.Run("no token is 407", func(t *testing.T) {
		code, c, _ := connect(t, sock, upHost, "")
		c.Close()
		if code != 407 {
			t.Fatalf("status %d", code)
		}
	})

	t.Run("token for another tool is 403", func(t *testing.T) {
		other, _, _ := minter.Mint("slack_post", "#general", "h", "task-1")
		code, c, _ := connect(t, sock, upHost, other)
		c.Close()
		if code != 403 {
			t.Fatalf("status %d", code)
		}
	})

	t.Run("token from a rogue key is 403", func(t *testing.T) {
		_, rogue, _ := tokens.GenerateKey()
		bad, _, _ := tokens.NewMinter(rogue, 5*time.Second).Mint("jira_read", "OPS-1", "h", "task-1")
		code, c, _ := connect(t, sock, upHost, bad)
		c.Close()
		if code != 403 {
			t.Fatalf("status %d", code)
		}
	})

	t.Run("plain GET is 405", func(t *testing.T) {
		c, _ := net.Dial("unix", sock)
		defer c.Close()
		fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", upHost, upHost)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 405 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
}

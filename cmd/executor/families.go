package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Each family is a small function: take the job and (maybe) a credential,
// talk to the service, return a JSON-able result. Nothing here knows about
// policy, tokens, or the governor.

// --- echo: no service, no credential --------------------------------------------

func runEcho(j job) (any, error) {
	var args any
	json.Unmarshal(j.Args, &args)
	return map[string]any{"echo": args}, nil
}

// --- jira -------------------------------------------------------------------------

func runJira(j job, secret map[string]any, addr string) (any, error) {
	tok, _ := secret["api_token"].(string)
	if tok == "" {
		return nil, errors.New("no api_token in credential")
	}
	var args struct {
		TicketID string `json:"ticket_id"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(j.Args, &args); err != nil {
		return nil, err
	}
	switch j.Tool {
	case "jira_read":
		res, err := call("GET", fmt.Sprintf("http://%s/jira/issue/%s", addr, args.TicketID), tok, nil)
		if err != nil {
			return nil, err
		}
		// The source system's own classification decides how sensitive this
		// result is. We report it; the governor raises the task's taint to
		// at least this (and never below the manifest's floor).
		if m, ok := res.(map[string]any); ok && m["security"] == "confidential" {
			reportSensitivity(8)
		} else {
			reportSensitivity(1)
		}
		return res, nil
	case "jira_update":
		body := map[string]string{"status": args.Status}
		return call("PUT", fmt.Sprintf("http://%s/jira/issue/%s", addr, args.TicketID), tok, body)
	}
	return nil, fmt.Errorf("jira family does not implement %s", j.Tool)
}

// --- slack ------------------------------------------------------------------------

func runSlack(j job, secret map[string]any, addr string) (any, error) {
	tok, _ := secret["bot_token"].(string)
	if tok == "" {
		return nil, errors.New("no bot_token in credential")
	}
	var args struct {
		Channel string `json:"channel"`
		Text    string `json:"text"`
	}
	if err := json.Unmarshal(j.Args, &args); err != nil {
		return nil, err
	}
	if j.Tool != "slack_post" {
		return nil, fmt.Errorf("slack family does not implement %s", j.Tool)
	}
	return call("POST", fmt.Sprintf("http://%s/slack/chat.postMessage", addr), tok, map[string]string{"channel": args.Channel, "text": args.Text})
}

// sensitivity is what the family learned about the result's classification
// from the source system, 0 if it has no opinion. Written into the output
// envelope by main.
var sensitivity int

func reportSensitivity(n int) {
	if n > sensitivity {
		sensitivity = n
	}
}

// --- shared HTTP helper -------------------------------------------------------------

var client = &http.Client{Timeout: 5 * time.Second}

// useEgressProxy routes every connection the families make through the
// egress proxy's Unix socket: dial the socket, send CONNECT host:port with
// the governor token, and hand the established stream to net/http as if it
// were a direct connection. Works for http:// and https:// targets alike.
func useEgressProxy(sock, token string) {
	client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.Dial("unix", sock)
			if err != nil {
				return nil, fmt.Errorf("egress proxy: %w", err)
			}
			fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\n\r\n", addr, addr, token)
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
			if err != nil {
				c.Close()
				return nil, fmt.Errorf("egress proxy: %w", err)
			}
			if resp.StatusCode != 200 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
				c.Close()
				return nil, fmt.Errorf("egress proxy refused %s: %s", addr, strings.TrimSpace(string(body)))
			}
			// Nothing should be buffered past the 200, but keep it safe.
			if br.Buffered() > 0 {
				return &bufConn{Conn: c, r: br}, nil
			}
			return c, nil
		},
		DisableKeepAlives: true, // one call, one connection
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// callID is the token's jti, set by main, sent to the service as a header so
// the service's own log can be joined to the governor's audit record.
var callID string

func call(method, url, bearer string, body any) (any, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if callID != "" {
		req.Header.Set("X-Perimeter-Call", callID)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s %s: %s: %s", method, url, resp.Status, bytes.TrimSpace(data))
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return string(data), nil
	}
	return out, nil
}

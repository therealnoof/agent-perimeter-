package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
		return call("GET", fmt.Sprintf("http://%s/jira/issue/%s", addr, args.TicketID), tok, nil)
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

// --- shared HTTP helper -------------------------------------------------------------

var client = &http.Client{Timeout: 5 * time.Second}

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

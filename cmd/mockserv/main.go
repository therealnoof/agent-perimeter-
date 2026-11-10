// Command mockserv stands in for Jira and Slack so executors have something
// real to call. It checks for a bearer token, keeps a few issues in memory,
// and logs every request so a demo can show what actually reached the
// service and with which credential.
//
//	mockserv -listen 127.0.0.1:9811 -jira-token T1 -slack-token T2
//
// Endpoints:
//
//	GET  /jira/issue/{id}                  → the issue
//	PUT  /jira/issue/{id}  {"status":…}    → updated issue
//	POST /slack/chat.postMessage {channel,text}
//	GET  /log                              → everything received, newest last
//
// Not part of the trust boundary. Deliberately simple.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type issue struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Status   string `json:"status"`
	Security string `json:"security"` // "" or "confidential"
}

var (
	mu     sync.Mutex // issues
	logMu  sync.Mutex // logLines; separate so handlers holding mu can log
	issues = map[string]*issue{
		"OPS-1":  {ID: "OPS-1", Summary: "Printer on floor 3 jams", Status: "open"},
		"OPS-2":  {ID: "OPS-2", Summary: "VPN drops every hour", Status: "open"},
		"OPS-99": {ID: "OPS-99", Summary: "[CONFIDENTIAL] Pending breach notification draft", Status: "open", Security: "confidential"},
	}
	logLines []string
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9811", "address to serve on")
	jiraTok := flag.String("jira-token", "jira-demo-token", "bearer token jira endpoints require")
	slackTok := flag.String("slack-token", "slack-demo-token", "bearer token slack endpoints require")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/jira/issue/", auth(*jiraTok, jiraHandler))
	mux.HandleFunc("/slack/chat.postMessage", auth(*slackTok, slackHandler))
	mux.HandleFunc("/log", func(w http.ResponseWriter, r *http.Request) {
		logMu.Lock()
		defer logMu.Unlock()
		for _, l := range logLines {
			fmt.Fprintln(w, l)
		}
	})
	log.Printf("mockserv: listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

// auth requires the right bearer token and logs the attempt either way.
func auth(want string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		ok := got == want
		record("%s %s auth=%s call=%s", r.Method, r.URL.Path, mask(got, ok), short(r.Header.Get("X-Perimeter-Call")))
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		next(w, r)
	}
}

func jiraHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/jira/issue/")
	mu.Lock()
	defer mu.Unlock()
	is, ok := issues[id]
	if !ok {
		http.Error(w, `{"error":"no such issue"}`, 404)
		return
	}
	switch r.Method {
	case "GET":
		json.NewEncoder(w).Encode(is)
	case "PUT":
		var body struct {
			Status string `json:"status"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Status != "" {
			is.Status = body.Status
		}
		record("  %s status -> %s", id, is.Status)
		json.NewEncoder(w).Encode(is)
	default:
		http.Error(w, `{"error":"method"}`, 405)
	}
}

func slackHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Channel string `json:"channel"`
		Text    string `json:"text"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	record("  slack %s: %q", body.Channel, body.Text)
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "channel": body.Channel, "ts": fmt.Sprint(time.Now().Unix())})
}

func record(format string, a ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	line := time.Now().Format("15:04:05.000") + " " + fmt.Sprintf(format, a...)
	logLines = append(logLines, line)
	log.Print(line)
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	if s == "" {
		return "-"
	}
	return s
}

func mask(tok string, ok bool) string {
	if tok == "" {
		return "none"
	}
	tail := tok
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	if ok {
		return "ok(…" + tail + ")"
	}
	return "BAD(…" + tail + ")"
}

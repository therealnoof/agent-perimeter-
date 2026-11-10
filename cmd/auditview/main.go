// Command auditview is the read-only dashboard: one page that shows the
// governor's audit chain as traces, the taint trajectory, approvals,
// credential releases joined to executor records, what reached the
// services, and a behavioural profile of the agent.
//
//	auditview -audit run/audit3.jsonl -secretsd-log run/secretsd.log -mock-addr 127.0.0.1:9811
//	          [-listen 127.0.0.1:9800] [-tls-cert C -tls-key K]
//
// It is NOT part of the trust boundary and must never become part of it:
//   - It only reads: the chain file, the sidecar log, the mock's /log.
//   - It never talks to agentd, secretsd or the worker.
//   - It re-verifies the whole chain on every change, so "chain intact" on
//     the page is a fresh fact, not a cached one.
//   - It binds to loopback by default. A non-loopback -listen is refused
//     unless TLS is configured, so the audit trail is never served in clear
//     text on a network by accident.
//
// Everything it shows is derived from records the governor already wrote.
// The behavioural profile is observational: it is for a human's eyes and
// never feeds policy.
package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed static
var static embed.FS

func main() {
	listen := flag.String("listen", "127.0.0.1:9800", "address to serve on; non-loopback requires -tls-cert/-tls-key")
	tlsCert := flag.String("tls-cert", "", "TLS certificate (PEM); enables HTTPS")
	tlsKey := flag.String("tls-key", "", "TLS private key (PEM)")
	auditPath := flag.String("audit", "", "audit chain to watch (required)")
	secretsLog := flag.String("secretsd-log", "", "secretsd log (JSON lines on stderr) to watch")
	mockAddr := flag.String("mock-addr", "", "mockserv address, for its /log")
	poll := flag.Duration("poll", 500*time.Millisecond, "how often to check sources for changes")
	flag.Parse()

	if *auditPath == "" {
		log.Fatal("auditview: -audit is required")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatalf("auditview: -listen: %v", err)
	}
	loopback := host == "127.0.0.1" || host == "localhost" || host == "::1"
	if !loopback && (*tlsCert == "" || *tlsKey == "") {
		log.Fatalf("auditview: refusing to serve %s without TLS; pass -tls-cert and -tls-key, or bind 127.0.0.1", *listen)
	}

	w := newWatcher(*auditPath, *secretsLog, *mockAddr, *poll)
	go w.run()

	sub, err := fs.Sub(static, "static")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", noCache(http.FileServer(http.FS(sub))))
	mux.HandleFunc("/api/state", w.serveState)
	mux.HandleFunc("/events", w.serveEvents)

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	fmt.Fprintf(os.Stderr, "auditview: %s://%s  (watching %s)\n", scheme, *listen, *auditPath)
	if scheme == "https" {
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	log.Fatal(srv.ListenAndServe())
}

// noCache keeps the page fresh across rebuilds during the PoC.
func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", "no-store")
		// Nothing here needs a referrer, framing, or scripts from elsewhere.
		rw.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		rw.Header().Set("X-Frame-Options", "DENY")
		rw.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasSuffix(r.URL.Path, ".js") {
			rw.Header().Set("Content-Type", "application/javascript")
		}
		h.ServeHTTP(rw, r)
	})
}

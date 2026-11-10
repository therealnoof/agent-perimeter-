// Command auditview is the read-only dashboard: one page that shows the
// governor's audit chain as traces, the taint trajectory, approvals,
// credential releases joined to executor records, what reached the
// services, and a behavioural profile of the agent.
//
//	auditview -audit run/audit3.jsonl -secretsd-log run/secretsd.log -mock-addr 127.0.0.1:9811
//	          [-listen 0.0.0.0:9800] [-tls-cert C -tls-key K] [-plaintext]
//
// It always serves HTTPS. With -tls-cert/-tls-key it uses those; without,
// it generates a self-signed ECDSA P-256 certificate at startup (valid 30
// days, SANs for localhost and every local address) and prints the SHA-256
// fingerprint so the browser's warning can be checked against it. Plain
// HTTP is available only with -plaintext AND a loopback -listen.
//
// It is NOT part of the trust boundary and must never become part of it:
//   - It only reads: the chain file, the sidecar log, the mock's /log.
//   - It never talks to agentd, secretsd or the worker.
//   - It re-verifies the whole chain on every change, so "chain intact" on
//     the page is a fresh fact, not a cached one.
//   - It never serves the audit trail in clear text on a network: HTTPS is
//     the default, and -plaintext works only on loopback.
//
// Everything it shows is derived from records the governor already wrote.
// The behavioural profile is observational: it is for a human's eyes and
// never feeds policy.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed static
var static embed.FS

func main() {
	listen := flag.String("listen", "0.0.0.0:9800", "address to serve on (HTTPS)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate (PEM); default: self-signed generated at startup")
	tlsKey := flag.String("tls-key", "", "TLS private key (PEM)")
	plaintext := flag.Bool("plaintext", false, "serve plain HTTP; allowed only on a loopback -listen")
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
	if *plaintext && !loopback {
		log.Fatalf("auditview: -plaintext is allowed only on a loopback address, not %s", *listen)
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("auditview: -tls-cert and -tls-key go together")
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
	if *plaintext {
		fmt.Fprintf(os.Stderr, "auditview: http://%s  (PLAINTEXT, loopback only; watching %s)\n", *listen, *auditPath)
		log.Fatal(srv.ListenAndServe())
	}

	var cert tls.Certificate
	if *tlsCert != "" {
		cert, err = tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("auditview: load TLS pair: %v", err)
		}
	} else {
		cert, err = selfSigned()
		if err != nil {
			log.Fatalf("auditview: self-signed certificate: %v", err)
		}
		sum := sha256.Sum256(cert.Certificate[0])
		fmt.Fprintf(os.Stderr, "auditview: self-signed certificate, SHA-256 fingerprint %s\n", colonHex(sum[:]))
		fmt.Fprintln(os.Stderr, "auditview: your browser will warn once; compare its fingerprint with the line above, or pass -tls-cert/-tls-key")
	}
	srv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	fmt.Fprintf(os.Stderr, "auditview: https://%s  (watching %s)\n", displayAddr(*listen), *auditPath)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// selfSigned makes an in-memory ECDSA P-256 certificate for this host:
// localhost, 127.0.0.1, and every non-loopback address the host has, so
// the SAN matches however the operator reaches it. Valid for 30 days.
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	hostname, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "agentd auditview (" + hostname + ")"},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", hostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ipn.IP)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func colonHex(b []byte) string {
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02X", c)
	}
	return sb.String()
}

// displayAddr turns 0.0.0.0:9800 into something a person can open.
func displayAddr(listen string) string {
	host, port, _ := net.SplitHostPort(listen)
	if host != "0.0.0.0" && host != "" && host != "::" {
		return listen
	}
	hostname, _ := os.Hostname()
	return "<this-host>:" + port + "  (e.g. https://" + hostname + ":" + port + ")"
}

// noCache keeps the page fresh across rebuilds during the PoC.
func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", "no-store")
		// Nothing here needs a referrer, framing, or scripts from elsewhere.
		rw.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		rw.Header().Set("X-Frame-Options", "DENY")
		rw.Header().Set("Referrer-Policy", "no-referrer")
		if r.TLS != nil {
			rw.Header().Set("Strict-Transport-Security", "max-age=86400")
		}
		if strings.HasSuffix(r.URL.Path, ".js") {
			rw.Header().Set("Content-Type", "application/javascript")
		}
		h.ServeHTTP(rw, r)
	})
}

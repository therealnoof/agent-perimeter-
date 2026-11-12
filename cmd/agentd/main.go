package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/therealnoof/agent-perimeter/internal/tokens"
)

func generateGovKey() (ed25519.PublicKey, ed25519.PrivateKey, error) { return tokens.GenerateKey() }
func fingerprint(pub ed25519.PublicKey) string                       { return tokens.Fingerprint(pub) }

// version is stamped by the release workflow (-ldflags "-X main.version=v0.4.0");
// a local build reports "dev".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "version":
		fmt.Println("agentd", version)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "agentd: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentd: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  agentd keygen -out run/governor.key                      (once; also writes run/governor.pub)
  agentd version
  agentd run -manifest M.json -pubkey K.pub -policies DIR -audit LOG.jsonl -gov-key run/governor.key
             [-worker-user U] [-executor BIN] [-secrets-sock SOCK] [-approver cli|deny] [-dry-run] [-kill-dir DIR] -- CMD [ARGS...]
  agentd verify -audit LOG.jsonl`)
}

// cmdKeygen writes a new governor token-signing key, mode 0600. Run once per
// governor installation; start secretsd with the matching public key, which
// `agentd run` writes to -gov-pub-out.
func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "where to write the private key (hex, mode 0600)")
	pubOut := fs.String("pub-out", "", "where to write the public key (hex); default: <out> with .pub extension")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("keygen: -out is required")
	}
	if *pubOut == "" {
		*pubOut = strings.TrimSuffix(*out, filepath.Ext(*out)) + ".pub"
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("keygen: %s exists; refusing to overwrite", *out)
	}
	pub, priv, err := generateGovKey()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(*pubOut, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("governor key written to %s, public key to %s (fingerprint %s)\n", *out, *pubOut, fingerprint(pub)[:12])
	return nil
}

// cmdVerify walks the chain and prints the result. Exit status is the answer.
func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	auditPath := fs.String("audit", "", "path to the audit chain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *auditPath == "" {
		return fmt.Errorf("verify: -audit is required")
	}
	n, err := verifyChain(*auditPath)
	if err != nil {
		return err
	}
	fmt.Printf("ok: %d records, chain intact\n", n)
	return nil
}

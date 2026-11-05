// Command sign-manifest is the operator's offline tool for the manifest
// signing key. It never runs on the same host as agentd in a real deployment;
// in the PoC it does, but the private key stays out of the repo.
//
//	sign-manifest gen-key -priv PATH -pub PATH
//	sign-manifest sign    -priv PATH -in M.json -out M.json.sig
//	sign-manifest verify  -pub  PATH -in M.json -sig M.json.sig
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sign-manifest gen-key|sign|verify ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "gen-key":
		err = genKey(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign-manifest: %v\n", err)
		os.Exit(1)
	}
}

func genKey(args []string) error {
	fs := flag.NewFlagSet("gen-key", flag.ContinueOnError)
	privPath := fs.String("priv", "", "where to write the private key (hex)")
	pubPath := fs.String("pub", "", "where to write the public key (hex)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *privPath == "" || *pubPath == "" {
		return fmt.Errorf("-priv and -pub are required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// 0600 on the private key; the public key can be world-readable.
	if err := os.WriteFile(*privPath, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(*pubPath, []byte(hex.EncodeToString(pub)+"\n"), 0o644)
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	privPath := fs.String("priv", "", "private key (hex)")
	in := fs.String("in", "", "manifest to sign")
	out := fs.String("out", "", "where to write the detached signature (hex)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *privPath == "" || *in == "" || *out == "" {
		return fmt.Errorf("-priv, -in and -out are required")
	}
	privHex, err := os.ReadFile(*privPath)
	if err != nil {
		return err
	}
	priv, err := hex.DecodeString(strings.TrimSpace(string(privHex)))
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key is not a valid Ed25519 key")
	}
	body, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	// We sign the exact bytes of the file. agentd verifies the exact bytes
	// before parsing. Reformatting the JSON invalidates the signature, which
	// is the point.
	sig := ed25519.Sign(ed25519.PrivateKey(priv), body)
	return os.WriteFile(*out, []byte(hex.EncodeToString(sig)+"\n"), 0o644)
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "public key (hex)")
	in := fs.String("in", "", "manifest")
	sigPath := fs.String("sig", "", "detached signature (hex)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubPath == "" || *in == "" || *sigPath == "" {
		return fmt.Errorf("-pub, -in and -sig are required")
	}
	pubHex, _ := os.ReadFile(*pubPath)
	pub, err := hex.DecodeString(strings.TrimSpace(string(pubHex)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("public key is not a valid Ed25519 key")
	}
	body, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	sigHex, _ := os.ReadFile(*sigPath)
	sig, err := hex.DecodeString(strings.TrimSpace(string(sigHex)))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), body, sig) {
		return fmt.Errorf("signature does not verify for %s", *in)
	}
	return nil
}

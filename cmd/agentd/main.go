package main

import (
	"flag"
	"fmt"
	"os"
)

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
  agentd run -manifest M.json -pubkey K.pub -audit LOG.jsonl [-worker-uid N] [-dry-run] [-kill-dir DIR] -- CMD [ARGS...]
  agentd verify -audit LOG.jsonl`)
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

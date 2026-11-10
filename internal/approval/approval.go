package approval

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout is how long a prompt waits before resolving to deny.
const DefaultTimeout = 60 * time.Second

// Prompt is what the approver sees. Every field is governor-authored except
// Justification, which is agent text and is hidden by default.
type Prompt struct {
	TaskID        string
	Tool          string
	Target        string
	TaintHWM      int
	Rule          string // which policy routed this here
	ArgsHash      string
	Justification string // agent-authored; shown only on request
}

// Outcome is the approver's answer.
type Outcome struct {
	Approved   bool
	ApproverID string // who answered, for the audit record (A-5)
	ReasonCode string // "approved", "declined", "approval_timeout", "approval_unavailable"
}

// Approver answers prompts. Implementations must be safe for sequential use;
// the governor serialises calls.
type Approver interface {
	Ask(p Prompt) Outcome
}

// --- CLI ---------------------------------------------------------------------

// CLI prompts on a terminal. in is normally os.Stdin, out os.Stderr (so the
// prompt is visible even when stdout is redirected).
type CLI struct {
	In      io.Reader
	Out     io.Writer
	Timeout time.Duration
	Who     string // approver id; defaults to the current user

	mu    sync.Mutex  // one prompt at a time
	once  sync.Once   // start the reader exactly once per CLI
	lines chan string // every line typed, for the life of the process
}

// NewCLI returns a terminal approver on stdin/stderr.
func NewCLI(timeout time.Duration) *CLI {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &CLI{In: os.Stdin, Out: os.Stderr, Timeout: timeout, Who: currentUser()}
}

// Ask shows the prompt and waits for a, d, or j. Timeout or EOF is deny.
func (c *CLI) Ask(p Prompt) Outcome {
	c.mu.Lock()
	defer c.mu.Unlock()

	// One reader goroutine for the life of this CLI. A reader per Ask would
	// leave the previous one blocked on Scan, stealing the next prompt's
	// keystrokes (found in the first interactive demo).
	c.once.Do(func() {
		c.lines = make(chan string, 16)
		go func() {
			sc := bufio.NewScanner(c.In)
			for sc.Scan() {
				c.lines <- strings.ToLower(strings.TrimSpace(sc.Text()))
			}
			close(c.lines)
		}()
	})

	// Anything typed while no prompt was open is not an answer to this
	// one. Drain it so a stray "a" from earlier cannot approve this call.
	for {
		select {
		case _, ok := <-c.lines:
			if !ok {
				fmt.Fprintln(c.Out, "\n[approval] input closed: DENIED (approval_unavailable)")
				return Outcome{false, c.Who, "approval_unavailable"}
			}
			continue
		default:
		}
		break
	}

	deadline := time.Now().Add(c.Timeout)
	c.render(p, false, deadline)
	lines := c.lines

	timer := time.NewTimer(c.Timeout)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			fmt.Fprintf(c.Out, "\n[approval] no answer in %s: DENIED (approval_timeout)\n", c.Timeout)
			return Outcome{false, c.Who, "approval_timeout"}
		case line, ok := <-lines:
			if !ok {
				fmt.Fprintln(c.Out, "\n[approval] input closed: DENIED (approval_unavailable)")
				return Outcome{false, c.Who, "approval_unavailable"}
			}
			switch line {
			case "a", "approve", "y", "yes":
				fmt.Fprintln(c.Out, "[approval] APPROVED")
				return Outcome{true, c.Who, "approved"}
			case "d", "deny", "n", "no":
				fmt.Fprintln(c.Out, "[approval] DECLINED")
				return Outcome{false, c.Who, "declined"}
			case "j", "justification":
				// The one way the agent's words reach the human: on request,
				// clearly labelled, and never as the default view.
				c.render(p, true, deadline)
			default:
				fmt.Fprintf(c.Out, "[approval] a=approve d=deny j=show agent justification (%ds left): ", int(time.Until(deadline).Seconds()))
			}
		}
	}
}

func (c *CLI) render(p Prompt, withJustification bool, deadline time.Time) {
	w := c.Out
	fmt.Fprintln(w)
	fmt.Fprintln(w, "┌─ APPROVAL REQUIRED ─────────────────────────────────────────")
	fmt.Fprintf(w, "│ task      %s\n", p.TaskID)
	fmt.Fprintf(w, "│ tool      %s\n", p.Tool)
	fmt.Fprintf(w, "│ target    %s\n", p.Target)
	fmt.Fprintf(w, "│ taint     %d  (highest sensitivity this task has touched)\n", p.TaintHWM)
	fmt.Fprintf(w, "│ rule      %s\n", p.Rule)
	fmt.Fprintf(w, "│ args      sha256:%s…\n", shortHash(p.ArgsHash))
	if withJustification {
		fmt.Fprintln(w, "│")
		fmt.Fprintln(w, "│ ── AGENT'S OWN WORDS (untrusted; may be injected) ──")
		for _, line := range wrap(p.Justification, 60) {
			fmt.Fprintf(w, "│   %s\n", line)
		}
	} else {
		fmt.Fprintln(w, "│ (agent justification hidden; press j to show)")
	}
	fmt.Fprintln(w, "└──────────────────────────────────────────────────────────────")
	fmt.Fprintf(w, "[approval] a=approve d=deny j=show agent justification (%ds): ", int(time.Until(deadline).Seconds()))
}

// --- DenyAll / AllowAll -----------------------------------------------------------

// DenyAll answers every prompt with deny. For headless runs.
type DenyAll struct{}

func (DenyAll) Ask(Prompt) Outcome { return Outcome{false, "none", "approval_unavailable"} }

// AllowAll answers every prompt with approve. FOR TESTS AND CANNED DEMOS ONLY.
type AllowAll struct{ Who string }

func (a AllowAll) Ask(Prompt) Outcome { return Outcome{true, a.Who, "approved"} }

// --- helpers -----------------------------------------------------------------------

func currentUser() string {
	// Under sudo, the human is SUDO_USER, not root.
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return fmt.Sprintf("uid:%d", os.Getuid())
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func wrap(s string, width int) []string {
	if s == "" {
		return []string{"(empty)"}
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		line := ""
		for _, w := range words {
			if len(line)+1+len(w) > width && line != "" {
				out = append(out, line)
				line = w
				continue
			}
			if line == "" {
				line = w
			} else {
				line += " " + w
			}
		}
		out = append(out, line)
	}
	return out
}

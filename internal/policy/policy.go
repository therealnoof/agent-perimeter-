package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/therealnoof/agent-perimeter/internal/manifest"
)

// Verdict is one of three outcomes. There is no fourth.
type Verdict string

const (
	Allow   Verdict = "allow"
	Deny    Verdict = "deny"
	Approve Verdict = "approve" // route to a human; the governor decides what that means
)

// Entity type names a policy author uses. Fixed here so policies and the
// governor cannot drift apart.
const (
	TypeAgent  types.EntityType = "Agent"
	TypeAction types.EntityType = "Action"
	TypeTarget types.EntityType = "Target"
)

// NoTarget is the resource id used when a tool declares no resource argument.
const NoTarget = "-"

// Input is every fact policy may consider. It is built by the governor, not
// parsed from the request. Compare it with schema.Request: Tool and TaskID
// come through, Args is reduced to a hash and a bounded target, Justification
// does not exist here.
type Input struct {
	// From the manifest.
	Role               string
	DataClearance      string
	MaxDelegationDepth int

	// About the tool being requested. ToolKnown is false when the manifest has
	// no such tool; the other Tool* fields are then zero.
	ToolKnown        bool
	ToolName         string
	ToolKind         manifest.Kind
	ToolDirection    manifest.Direction
	SensitivityFloor *int
	MaxCallsPerTask  int

	// Target is the value of the tool's declared resource argument, or
	// NoTarget. It is schema-bounded (enum or pattern), never free text.
	Target string

	// From the task store (G-7).
	CallCount       int // allowed calls of this tool so far in this task
	TaintHWM        int
	DelegationDepth int

	// About the request. ArgsHash is the hex SHA-256 of the canonical args.
	ArgsHash string
}

// Decision is the verdict plus which rule produced it, for the audit record.
type Decision struct {
	Verdict    Verdict
	Rule       string // from the fired policy's @id annotation, e.g. "flow.sensitivity_floor"
	ReasonCode string // for the structured refusal sent to the worker (A-4)
}

// Engine holds a loaded, signature-verified policy set.
//
// hard is the same set with every @verdict("approve") forbid removed. It
// answers the question Cedar's diagnostic cannot: when the full set denies
// and only overridable forbids fired, would anything have PERMITTED the
// request? If not, there is nothing for a human to override and the answer
// is deny, not approve.
type Engine struct {
	set   *cedar.PolicySet
	hard  *cedar.PolicySet
	files []string // for the audit "start" record
}

// Errors callers can test for.
var (
	ErrNoPolicies   = errors.New("policy: no .cedar files found")
	ErrNoSignature  = errors.New("policy: signature file missing")
	ErrBadSignature = errors.New("policy: signature does not verify")
	ErrParse        = errors.New("policy: parse error")
)

// Load reads every *.cedar file in dir, verifies the detached *.cedar.sig
// beside each against pub, and parses them into one policy set. Like the
// manifest loader, it verifies bytes BEFORE parsing them. Requirement P-1.
func Load(dir string, pub ed25519.PublicKey) (*Engine, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("policy: public key is not a valid Ed25519 key")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.cedar"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("%w in %s", ErrNoPolicies, dir)
	}
	sort.Strings(paths) // deterministic policy IDs run to run

	set, hard := cedar.NewPolicySet(), cedar.NewPolicySet()
	var files []string
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("policy: read %s: %w", p, err)
		}
		sigHex, err := os.ReadFile(p + ".sig")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("%w: %s.sig", ErrNoSignature, p)
			}
			return nil, fmt.Errorf("policy: read signature: %w", err)
		}
		sig, err := hex.DecodeString(strings.TrimSpace(string(sigHex)))
		if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, raw, sig) {
			return nil, fmt.Errorf("%w: %s", ErrBadSignature, p)
		}

		// Only now parse. Policy IDs are "<file>:<n>" so a diagnostic can be
		// traced to a file even when the author forgot an @id.
		list, err := cedar.NewPolicyListFromBytes(filepath.Base(p), raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrParse, p, err)
		}
		for i, pol := range list {
			id := types.PolicyID(fmt.Sprintf("%s:%d", filepath.Base(p), i))
			set.Add(id, pol)
			if !overridable(pol) {
				hard.Add(id, pol)
			}
		}
		files = append(files, filepath.Base(p))
	}
	return &Engine{set: set, hard: hard, files: files}, nil
}

// overridable reports whether a policy is a forbid a human may override.
func overridable(p *cedar.Policy) bool {
	return p.Effect() == cedar.Forbid && annotation(p, "verdict") == "approve"
}

// LoadUnsigned parses policies from in-memory text with no signature check.
// For tests only; the governor never calls it. Policy IDs are "<name>:<n>".
func LoadUnsigned(name string, text []byte) (*Engine, error) {
	list, err := cedar.NewPolicyListFromBytes(name, text)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParse, err)
	}
	set, hard := cedar.NewPolicySet(), cedar.NewPolicySet()
	for i, pol := range list {
		id := types.PolicyID(fmt.Sprintf("%s:%d", name, i))
		set.Add(id, pol)
		if !overridable(pol) {
			hard.Add(id, pol)
		}
	}
	return &Engine{set: set, hard: hard, files: []string{name}}, nil
}

// Files returns the policy file names that were loaded, for the audit log.
func (e *Engine) Files() []string { return e.files }

// Decide evaluates one request. It never returns an error: a malformed or
// unevaluable policy is a Deny with rule "engine.error", because an
// enforcement point that cannot decide must fail closed.
//
// Two checks run in Go before Cedar is consulted, because they are properties
// of the governor rather than of any role's policy and must hold even if an
// operator ships an empty policy file:
//   - G-8: delegation depth over the manifest ceiling.
//   - base: the tool must exist in the manifest at all.
func (e *Engine) Decide(in Input) Decision {
	if in.DelegationDepth > in.MaxDelegationDepth {
		return Decision{Deny, "escalation.delegation_depth", "delegation_depth_exceeded"}
	}
	if !in.ToolKnown {
		return Decision{Deny, "base.unknown_tool", "tool_not_in_manifest"}
	}
	return e.evaluate(in)
}

// evaluate is the Cedar-only part of Decide, separated so tests can exercise
// the policy files without the Go pre-checks in front of them.
func (e *Engine) evaluate(in Input) Decision {
	req := cedar.Request{
		Principal: cedar.NewEntityUID(TypeAgent, types.String(in.Role)),
		Action:    cedar.NewEntityUID(TypeAction, types.String(in.ToolName)),
		Resource:  cedar.NewEntityUID(TypeTarget, types.String(in.Target)),
		Context:   buildContext(in),
	}

	// Entities: the principal carries its clearance so a policy can say
	// `principal.clearance == "internal"`. Target and Action are bare ids.
	ents := cedar.EntityMap{}
	agent := cedar.NewEntityUID(TypeAgent, types.String(in.Role))
	ents[agent] = cedar.Entity{
		UID:        agent,
		Attributes: cedar.NewRecord(cedar.RecordMap{"clearance": types.String(in.DataClearance)}),
	}

	dec, diag := cedar.Authorize(e.set, ents, req)
	if len(diag.Errors) > 0 {
		// A policy that errored (e.g. referenced a missing context key without
		// `has`) is a bug in the policy, and the safe answer is deny.
		return Decision{Deny, "engine.error", "policy_evaluation_error"}
	}
	if dec == cedar.Allow {
		return Decision{Allow, e.ruleFor(diag, cedar.Permit, "base.default_permit"), ""}
	}

	// Deny. Was every forbid that fired overridable by a human?
	forbids := e.firedWithEffect(diag, cedar.Forbid)
	if len(forbids) == 0 {
		// Nothing forbade it; nothing permitted it either.
		return Decision{Deny, "base.default_deny", "no_permit_matched"}
	}
	rule := e.ruleFor(diag, cedar.Forbid, "base.forbid")
	for _, p := range forbids {
		if !overridable(p) {
			// At least one forbid is final. Nobody can override this.
			return Decision{Deny, rule, strings.ReplaceAll(rule, ".", "_")}
		}
	}

	// Only overridable forbids fired. That is "approve" only if something
	// would have permitted the request without them; otherwise there is no
	// grant for a human to confirm and the answer is still deny.
	hardDec, hardDiag := cedar.Authorize(e.hard, ents, req)
	if len(hardDiag.Errors) > 0 {
		return Decision{Deny, "engine.error", "policy_evaluation_error"}
	}
	if hardDec == cedar.Allow {
		return Decision{Approve, rule, strings.TrimPrefix(rule, "flow.")}
	}
	return Decision{Deny, "base.default_deny", "no_permit_matched"}
}

// buildContext packs the governor's facts into the Cedar context record.
// Optional facts are omitted rather than zeroed so a policy can test them
// with `context has sensitivity_floor`.
func buildContext(in Input) types.Record {
	m := cedar.RecordMap{
		"kind":                 types.String(in.ToolKind),
		"direction":            types.String(in.ToolDirection),
		"call_count":           types.Long(in.CallCount),
		"max_calls":            types.Long(in.MaxCallsPerTask),
		"taint_hwm":            types.Long(in.TaintHWM),
		"delegation_depth":     types.Long(in.DelegationDepth),
		"max_delegation_depth": types.Long(in.MaxDelegationDepth),
	}
	if in.SensitivityFloor != nil {
		m["sensitivity_floor"] = types.Long(*in.SensitivityFloor)
	}
	return cedar.NewRecord(m)
}

// firedWithEffect returns the policies in the diagnostic's reasons that have
// the given effect. Cedar reports every determining policy; for an allow
// those are the permits, for a deny those are the forbids (if any).
func (e *Engine) firedWithEffect(diag cedar.Diagnostic, eff cedar.Effect) []*cedar.Policy {
	var out []*cedar.Policy
	for _, r := range diag.Reasons {
		if p := e.set.Get(r.PolicyID); p != nil && p.Effect() == eff {
			out = append(out, p)
		}
	}
	return out
}

// ruleFor returns the @id of the first fired policy with the given effect, or
// its policy id if it has no annotation, or fallback if none fired.
func (e *Engine) ruleFor(diag cedar.Diagnostic, eff cedar.Effect, fallback string) string {
	for _, r := range diag.Reasons {
		p := e.set.Get(r.PolicyID)
		if p == nil || p.Effect() != eff {
			continue
		}
		if id := annotation(p, "id"); id != "" {
			return id
		}
		return string(r.PolicyID)
	}
	return fallback
}

// annotation reads one @key("value") annotation from a policy.
func annotation(p *cedar.Policy, key string) string {
	if v, ok := p.Annotations()[types.Ident(key)]; ok {
		return string(v)
	}
	return ""
}

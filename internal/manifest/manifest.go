package manifest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Kind classifies a tool's arguments. Requirement P-7.
//
//   - structured: every argument is bounded (an ID, an enum, a number, a path).
//     The schema fully constrains what can be sent.
//   - freeform: at least one argument is arbitrary text (a message body, a
//     comment). Text is the channel we cannot bound by schema, so policy
//     treats freeform + outbound as needing a human unless explicitly allowed.
type Kind string

const (
	KindStructured Kind = "structured"
	KindFreeform   Kind = "freeform"
)

// Direction says whether a tool brings data in or sends it out.
// Outbound tools are where exfiltration happens, so policy watches them.
type Direction string

const (
	DirInbound  Direction = "inbound"
	DirOutbound Direction = "outbound"
)

// Tool is one capability the role may use.
type Tool struct {
	Name      string    `json:"name"`
	Kind      Kind      `json:"kind"`
	Direction Direction `json:"direction"`

	// SensitivityFloor (0-10) is requirement P-6. When the task's taint
	// high-water mark reaches this value, an "allow" becomes "approve".
	// nil means no floor.
	SensitivityFloor *int `json:"sensitivity_floor,omitempty"`

	// MaxCallsPerTask caps how many times this tool may run in one task.
	// Enforced by the governor (G-7), never by a token. 0 means no cap.
	MaxCallsPerTask int `json:"max_calls_per_task,omitempty"`

	// ResourceArg names the args field whose value becomes the Cedar
	// `resource` (Target::"<value>") so policy can say "this channel but not
	// that one". The field's schema must be a string bounded by enum or
	// pattern, so an agent cannot put free text into an entity id. Empty
	// means the tool has no resource dimension.
	ResourceArg string `json:"resource_arg,omitempty"`

	// ResultSensitivity (0-10) is the sensitivity of data this tool RETURNS.
	// When the tool runs, the governor raises the task's taint high-water
	// mark to at least this level (D-2). Determined by the source, never by
	// inspecting the content. 0 means the result carries no sensitivity.
	ResultSensitivity int `json:"result_sensitivity,omitempty"`

	// ArgsSchema constrains the "args" object the agent sends. See
	// internal/schema for the subset of JSON Schema we support.
	ArgsSchema json.RawMessage `json:"args_schema"`
}

// Manifest is the signed, operator-authored description of one agent role.
type Manifest struct {
	Role          string `json:"role"`
	DataClearance string `json:"data_clearance"`

	// MaxDelegationDepth is requirement G-8. 0 (the default) means this role
	// may never act on behalf of another task.
	MaxDelegationDepth int `json:"max_delegation_depth"`

	Tools []Tool `json:"tools"`
}

// Tool returns the named tool, or nil if the role does not have it.
func (m *Manifest) Tool(name string) *Tool {
	for i := range m.Tools {
		if m.Tools[i].Name == name {
			return &m.Tools[i]
		}
	}
	return nil
}

// Errors callers can test for with errors.Is.
var (
	ErrNoSignature  = errors.New("manifest: signature file missing")
	ErrBadSignature = errors.New("manifest: signature does not verify")
	ErrBadKey       = errors.New("manifest: public key is not a valid Ed25519 key")
	ErrInvalid      = errors.New("manifest: content is invalid")
)

// Load reads a manifest from manifestPath, verifies the detached signature at
// manifestPath+".sig" against pub, and returns the parsed manifest.
//
// The order matters: we verify the raw bytes BEFORE parsing them. Parsing
// untrusted input is where bugs live, so we only parse what the operator
// signed. Requirement G-1.
func Load(manifestPath string, pub ed25519.PublicKey) (*Manifest, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrBadKey
	}

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("manifest: read %s: %w", manifestPath, err)
	}

	sigHex, err := os.ReadFile(manifestPath + ".sig")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoSignature
		}
		return nil, fmt.Errorf("manifest: read signature: %w", err)
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(sigHex)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrBadSignature
	}

	if !ed25519.Verify(pub, raw, sig) {
		return nil, ErrBadSignature
	}

	// Only now do we parse. The bytes are exactly what the operator signed.
	return parse(raw)
}

// LoadPublicKey reads a hex-encoded Ed25519 public key from a file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: read public key: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, ErrBadKey
	}
	return ed25519.PublicKey(key), nil
}

// boundedStringField checks that the args schema declares `field` as a string
// constrained by an enum or a pattern. It looks only at the shape it needs.
func boundedStringField(schemaRaw json.RawMessage, field string) error {
	var s struct {
		Properties map[string]struct {
			Type    string            `json:"type"`
			Enum    []json.RawMessage `json:"enum"`
			Pattern string            `json:"pattern"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schemaRaw, &s); err != nil {
		return fmt.Errorf("schema not readable: %v", err)
	}
	p, ok := s.Properties[field]
	switch {
	case !ok:
		return errors.New("not a declared property")
	case p.Type != "string":
		return errors.New("must be type string")
	case len(p.Enum) == 0 && p.Pattern == "":
		return errors.New("must be bounded by enum or pattern")
	}
	return nil
}

// parse decodes and sanity-checks manifest bytes that have already been
// signature-verified. It is strict: unknown fields are an error, because a
// typo in a manifest should fail loudly rather than silently grant or deny.
func parse(raw []byte) (*Manifest, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()

	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	if m.Role == "" {
		return nil, fmt.Errorf("%w: role is required", ErrInvalid)
	}
	if m.MaxDelegationDepth < 0 {
		return nil, fmt.Errorf("%w: max_delegation_depth must be >= 0", ErrInvalid)
	}
	if len(m.Tools) == 0 {
		return nil, fmt.Errorf("%w: at least one tool is required", ErrInvalid)
	}

	seen := map[string]bool{}
	for _, t := range m.Tools {
		if t.Name == "" {
			return nil, fmt.Errorf("%w: tool with empty name", ErrInvalid)
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("%w: duplicate tool %q", ErrInvalid, t.Name)
		}
		seen[t.Name] = true
		if t.Kind != KindStructured && t.Kind != KindFreeform {
			return nil, fmt.Errorf("%w: tool %q: kind must be structured or freeform", ErrInvalid, t.Name)
		}
		if t.Direction != DirInbound && t.Direction != DirOutbound {
			return nil, fmt.Errorf("%w: tool %q: direction must be inbound or outbound", ErrInvalid, t.Name)
		}
		if t.SensitivityFloor != nil && (*t.SensitivityFloor < 0 || *t.SensitivityFloor > 10) {
			return nil, fmt.Errorf("%w: tool %q: sensitivity_floor must be 0-10", ErrInvalid, t.Name)
		}
		if t.MaxCallsPerTask < 0 {
			return nil, fmt.Errorf("%w: tool %q: max_calls_per_task must be >= 0", ErrInvalid, t.Name)
		}
		if len(t.ArgsSchema) == 0 {
			return nil, fmt.Errorf("%w: tool %q: args_schema is required", ErrInvalid, t.Name)
		}
		if t.ResultSensitivity < 0 || t.ResultSensitivity > 10 {
			return nil, fmt.Errorf("%w: tool %q: result_sensitivity must be 0-10", ErrInvalid, t.Name)
		}
		if t.ResourceArg != "" {
			// The resource arg must be a bounded string, because its value
			// becomes a policy entity id. This is checked structurally against
			// the raw schema here; the schema package re-validates at runtime.
			if err := boundedStringField(t.ArgsSchema, t.ResourceArg); err != nil {
				return nil, fmt.Errorf("%w: tool %q: resource_arg %q: %v", ErrInvalid, t.Name, t.ResourceArg, err)
			}
		}
	}
	return &m, nil
}

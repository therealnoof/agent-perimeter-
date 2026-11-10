package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Limits on the request frame itself, before any schema is consulted. An
// agent that sends a 10 MB "justification" is not negotiating in good faith.
const (
	MaxFrameBytes         = 256 * 1024 // whole request
	MaxJustificationBytes = 4 * 1024   // justification string
	MaxToolNameBytes      = 64
	MaxTaskIDBytes        = 128
	MaxClientBytes        = 64
)

// Request is the fixed frame the agent sends. Nothing else is accepted.
// Requirement G-4: {tool, args, task_id, justification, client?}. The justification is
// carried for the human approver's optional view only; it never reaches
// policy (P-2) and this package never inspects its content.
type Request struct {
	Tool          string          `json:"tool"`
	Args          json.RawMessage `json:"args"`
	TaskID        string          `json:"task_id"`
	Justification string          `json:"justification"`

	// Client is the worker's self-description ("perimeter_client/0.3
	// python/3.12"). Optional, bounded, and observational only: it goes to
	// the audit record for fingerprinting and never to policy.
	Client string `json:"client,omitempty"`
}

// ErrInvalid wraps every validation failure so callers can errors.Is on it.
var ErrInvalid = errors.New("schema: invalid")

// ParseRequest decodes a raw frame into a Request, rejecting unknown fields,
// oversized fields and missing required ones. It does NOT validate args;
// that needs the tool's schema, which is looked up by the caller.
func ParseRequest(raw []byte) (*Request, error) {
	if len(raw) > MaxFrameBytes {
		return nil, fmt.Errorf("%w: frame exceeds %d bytes", ErrInvalid, MaxFrameBytes)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var r Request
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// Exactly one JSON value per frame.
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after request", ErrInvalid)
	}
	switch {
	case r.Tool == "":
		return nil, fmt.Errorf("%w: tool is required", ErrInvalid)
	case len(r.Tool) > MaxToolNameBytes:
		return nil, fmt.Errorf("%w: tool name too long", ErrInvalid)
	case r.TaskID == "":
		return nil, fmt.Errorf("%w: task_id is required", ErrInvalid)
	case len(r.TaskID) > MaxTaskIDBytes:
		return nil, fmt.Errorf("%w: task_id too long", ErrInvalid)
	case len(r.Justification) > MaxJustificationBytes:
		return nil, fmt.Errorf("%w: justification exceeds %d bytes", ErrInvalid, MaxJustificationBytes)
	case len(r.Client) > MaxClientBytes:
		return nil, fmt.Errorf("%w: client exceeds %d bytes", ErrInvalid, MaxClientBytes)
	case len(r.Args) == 0:
		return nil, fmt.Errorf("%w: args is required", ErrInvalid)
	}
	return &r, nil
}

// Schema is a compiled validator for one tool's args.
type Schema struct {
	node *node
}

// node is the parsed form of one schema object.
type node struct {
	Type                 string
	Properties           map[string]*node
	Required             []string
	AdditionalProperties bool
	Items                *node
	Enum                 []json.RawMessage
	Minimum, Maximum     *float64
	MinLength, MaxLength *int
	MaxItems             *int
	Pattern              *regexp.Regexp
}

// rawSchema is the JSON shape we accept when compiling.
type rawSchema struct {
	Type                 string                `json:"type"`
	Properties           map[string]*rawSchema `json:"properties"`
	Required             []string              `json:"required"`
	AdditionalProperties *bool                 `json:"additionalProperties"`
	Items                *rawSchema            `json:"items"`
	Enum                 []json.RawMessage     `json:"enum"`
	Minimum              *float64              `json:"minimum"`
	Maximum              *float64              `json:"maximum"`
	MinLength            *int                  `json:"minLength"`
	MaxLength            *int                  `json:"maxLength"`
	MaxItems             *int                  `json:"maxItems"`
	Pattern              *string               `json:"pattern"`
}

// Compile parses a schema. Unknown keywords are an error: a schema that uses a
// keyword we do not implement would silently not constrain anything, which is
// exactly the failure we want to catch at manifest load, not at request time.
func Compile(raw json.RawMessage) (*Schema, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var rs rawSchema
	if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("schema: compile: %w", err)
	}
	n, err := build(&rs, "$")
	if err != nil {
		return nil, err
	}
	return &Schema{node: n}, nil
}

func build(rs *rawSchema, path string) (*node, error) {
	if rs == nil {
		return nil, fmt.Errorf("schema: %s: empty schema", path)
	}
	switch rs.Type {
	case "object", "string", "integer", "number", "boolean", "array":
	case "":
		return nil, fmt.Errorf("schema: %s: type is required", path)
	default:
		return nil, fmt.Errorf("schema: %s: unsupported type %q", path, rs.Type)
	}
	n := &node{
		Type:     rs.Type,
		Required: rs.Required,
		Enum:     rs.Enum,
		Minimum:  rs.Minimum, Maximum: rs.Maximum,
		MinLength: rs.MinLength, MaxLength: rs.MaxLength,
		MaxItems: rs.MaxItems,
	}
	// additionalProperties defaults to FALSE. This is the one place we are
	// stricter than JSON Schema's default, on purpose.
	n.AdditionalProperties = rs.AdditionalProperties != nil && *rs.AdditionalProperties

	if rs.Type == "object" {
		n.Properties = make(map[string]*node, len(rs.Properties))
		for name, child := range rs.Properties {
			c, err := build(child, path+"."+name)
			if err != nil {
				return nil, err
			}
			n.Properties[name] = c
		}
		for _, req := range rs.Required {
			if _, ok := n.Properties[req]; !ok {
				return nil, fmt.Errorf("schema: %s: required %q is not a declared property", path, req)
			}
		}
	}
	if rs.Type == "array" {
		if rs.Items == nil {
			return nil, fmt.Errorf("schema: %s: array needs items", path)
		}
		c, err := build(rs.Items, path+"[]")
		if err != nil {
			return nil, err
		}
		n.Items = c
	}
	if rs.Pattern != nil {
		re, err := regexp.Compile(*rs.Pattern)
		if err != nil {
			return nil, fmt.Errorf("schema: %s: bad pattern: %w", path, err)
		}
		n.Pattern = re
	}
	return n, nil
}

// Validate checks args against the schema. The error names the path of the
// first failure so a developer can fix their agent; the governor itself only
// cares that it is non-nil.
func (s *Schema) Validate(args json.RawMessage) error {
	var v any
	dec := json.NewDecoder(strings.NewReader(string(args)))
	dec.UseNumber() // keep numbers exact so integer checks are honest
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("%w: args: %v", ErrInvalid, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: args: trailing data", ErrInvalid)
	}
	return check(s.node, v, "$")
}

func check(n *node, v any, path string) error {
	switch n.Type {
	case "object":
		obj, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: %s: expected object", ErrInvalid, path)
		}
		for _, req := range n.Required {
			if _, ok := obj[req]; !ok {
				return fmt.Errorf("%w: %s: missing required %q", ErrInvalid, path, req)
			}
		}
		for k, val := range obj {
			child, declared := n.Properties[k]
			if !declared {
				if n.AdditionalProperties {
					continue
				}
				return fmt.Errorf("%w: %s: unexpected field %q", ErrInvalid, path, k)
			}
			if err := check(child, val, path+"."+k); err != nil {
				return err
			}
		}
		return nil

	case "array":
		arr, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%w: %s: expected array", ErrInvalid, path)
		}
		if n.MaxItems != nil && len(arr) > *n.MaxItems {
			return fmt.Errorf("%w: %s: more than %d items", ErrInvalid, path, *n.MaxItems)
		}
		for i, el := range arr {
			if err := check(n.Items, el, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil

	case "string":
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%w: %s: expected string", ErrInvalid, path)
		}
		if n.MinLength != nil && len(s) < *n.MinLength {
			return fmt.Errorf("%w: %s: shorter than %d", ErrInvalid, path, *n.MinLength)
		}
		if n.MaxLength != nil && len(s) > *n.MaxLength {
			return fmt.Errorf("%w: %s: longer than %d", ErrInvalid, path, *n.MaxLength)
		}
		if n.Pattern != nil && !n.Pattern.MatchString(s) {
			return fmt.Errorf("%w: %s: does not match pattern", ErrInvalid, path)
		}
		return checkEnum(n, v, path)

	case "boolean":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("%w: %s: expected boolean", ErrInvalid, path)
		}
		return checkEnum(n, v, path)

	case "integer", "number":
		num, ok := v.(json.Number)
		if !ok {
			return fmt.Errorf("%w: %s: expected %s", ErrInvalid, path, n.Type)
		}
		f, err := num.Float64()
		if err != nil {
			return fmt.Errorf("%w: %s: bad number", ErrInvalid, path)
		}
		if n.Type == "integer" && (f != math.Trunc(f) || strings.ContainsAny(num.String(), ".eE")) {
			return fmt.Errorf("%w: %s: expected integer", ErrInvalid, path)
		}
		if n.Minimum != nil && f < *n.Minimum {
			return fmt.Errorf("%w: %s: below minimum %v", ErrInvalid, path, *n.Minimum)
		}
		if n.Maximum != nil && f > *n.Maximum {
			return fmt.Errorf("%w: %s: above maximum %v", ErrInvalid, path, *n.Maximum)
		}
		return checkEnum(n, v, path)
	}
	return fmt.Errorf("%w: %s: unknown type", ErrInvalid, path)
}

// checkEnum compares the value's JSON encoding against each allowed literal.
func checkEnum(n *node, v any, path string) error {
	if len(n.Enum) == 0 {
		return nil
	}
	got, _ := json.Marshal(v)
	for _, allowed := range n.Enum {
		var a any
		if err := json.Unmarshal(allowed, &a); err != nil {
			continue
		}
		want, _ := json.Marshal(a)
		if string(got) == string(want) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s: not one of the allowed values", ErrInvalid, path)
}

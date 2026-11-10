package schema

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const ticketSchema = `{
  "type": "object",
  "properties": {
    "ticket_id": {"type": "string", "pattern": "^[A-Z]+-[0-9]+$"},
    "status":    {"type": "string", "enum": ["open", "closed"]},
    "priority":  {"type": "integer", "minimum": 1, "maximum": 5},
    "labels":    {"type": "array", "items": {"type": "string", "maxLength": 20}, "maxItems": 5},
    "notify":    {"type": "boolean"}
  },
  "required": ["ticket_id", "status"]
}`

func mustCompile(t *testing.T, s string) *Schema {
	t.Helper()
	sc, err := Compile(json.RawMessage(s))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return sc
}

func TestValidArgs(t *testing.T) {
	sc := mustCompile(t, ticketSchema)
	ok := `{"ticket_id":"OPS-42","status":"open","priority":3,"labels":["a","b"],"notify":true}`
	if err := sc.Validate(json.RawMessage(ok)); err != nil {
		t.Fatalf("valid args rejected: %v", err)
	}
}

// G-4 cases from the attack table: extra field, wrong type, out of range.
func TestInvalidArgs(t *testing.T) {
	sc := mustCompile(t, ticketSchema)
	cases := map[string]string{
		"extra field":      `{"ticket_id":"OPS-1","status":"open","shell":"rm -rf /"}`,
		"wrong type":       `{"ticket_id":"OPS-1","status":"open","priority":"high"}`,
		"missing required": `{"ticket_id":"OPS-1"}`,
		"bad enum":         `{"ticket_id":"OPS-1","status":"deleted"}`,
		"below minimum":    `{"ticket_id":"OPS-1","status":"open","priority":0}`,
		"above maximum":    `{"ticket_id":"OPS-1","status":"open","priority":6}`,
		"float as integer": `{"ticket_id":"OPS-1","status":"open","priority":3.5}`,
		"bad pattern":      `{"ticket_id":"ops 1","status":"open"}`,
		"too many items":   `{"ticket_id":"OPS-1","status":"open","labels":["1","2","3","4","5","6"]}`,
		"item too long":    `{"ticket_id":"OPS-1","status":"open","labels":["` + strings.Repeat("x", 21) + `"]}`,
		"not an object":    `["OPS-1"]`,
		"trailing data":    `{"ticket_id":"OPS-1","status":"open"} {}`,
		"not json":         `{ticket_id: OPS-1}`,
	}
	for name, args := range cases {
		if err := sc.Validate(json.RawMessage(args)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

// Compile must refuse schemas that use keywords we do not implement, so a
// manifest author finds out at load time rather than getting a no-op check.
func TestCompileRejectsUnknownKeyword(t *testing.T) {
	_, err := Compile(json.RawMessage(`{"type":"object","properties":{"x":{"type":"string","format":"email"}}}`))
	if err == nil {
		t.Fatal("unknown keyword 'format' was accepted")
	}
	_, err = Compile(json.RawMessage(`{"type":"object","required":["nope"]}`))
	if err == nil {
		t.Fatal("required referencing undeclared property was accepted")
	}
	_, err = Compile(json.RawMessage(`{"type":"thing"}`))
	if err == nil {
		t.Fatal("unsupported type was accepted")
	}
}

func TestParseRequest(t *testing.T) {
	good := `{"tool":"jira_read","args":{"ticket_id":"OPS-1"},"task_id":"t-1","justification":"need it"}`
	r, err := ParseRequest([]byte(good))
	if err != nil {
		t.Fatalf("good request rejected: %v", err)
	}
	if r.Tool != "jira_read" || r.TaskID != "t-1" {
		t.Errorf("fields wrong: %+v", r)
	}
	withClient := `{"tool":"jira_read","args":{},"task_id":"t-1","justification":"","client":"perimeter_client/0.3"}`
	if r, err := ParseRequest([]byte(withClient)); err != nil || r.Client != "perimeter_client/0.3" {
		t.Errorf("client field: %v %+v", err, r)
	}

	bad := map[string]string{
		"unknown field":      `{"tool":"x","args":{},"task_id":"t","justification":"","labels":{}}`,
		"missing tool":       `{"args":{},"task_id":"t","justification":""}`,
		"missing task_id":    `{"tool":"x","args":{},"justification":""}`,
		"missing args":       `{"tool":"x","task_id":"t","justification":""}`,
		"long justification": `{"tool":"x","args":{},"task_id":"t","justification":"` + strings.Repeat("a", MaxJustificationBytes+1) + `"}`,
		"two frames":         `{"tool":"x","args":{},"task_id":"t","justification":""}{"tool":"y","args":{},"task_id":"t","justification":""}`,
	}
	for name, raw := range bad {
		if _, err := ParseRequest([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
	if _, err := ParseRequest(make([]byte, MaxFrameBytes+1)); !errors.Is(err, ErrInvalid) {
		t.Error("oversized frame accepted")
	}
}

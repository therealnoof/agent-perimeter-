package egressscan

import (
	"encoding/json"
	"strings"
	"testing"
)

func scan(t *testing.T, s *Scanner, js string) Report {
	t.Helper()
	return s.Scan(json.RawMessage(js))
}

// Attack table: "agent wraps a credential-looking string into a web_fetch
// URL query parameter" → high → deny.
func TestHighConfidence(t *testing.T) {
	s := New()
	cases := map[string]string{
		"aws key in url":    `{"url":"https://example.org/?k=AKIAIOSFODNN7EXAMPLE"}`,
		"github token":      `{"text":"use ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD please"}`,
		"slack token":       `{"text":"xoxb-123456789012-abcdefghij"}`,
		"private key":       `{"body":"-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}`,
		"token in url":      `{"url":"https://h/api?access_token=abcdefghijklmnop1234"}`,
		"basic auth in url": `{"url":"https://user:hunter2pass@host/path"}`,
		"nested array":      `{"items":[{"note":"ok"},{"note":"AKIAIOSFODNN7EXAMPLE"}]}`,
	}
	for name, js := range cases {
		r := scan(t, s, js)
		if r.Level != High {
			t.Errorf("%s: level %s, want high (%+v)", name, r.Level, r.Hits)
		}
	}
	// The hit names the path, never the value.
	r := scan(t, s, `{"items":[{"note":"ok"},{"note":"AKIAIOSFODNN7EXAMPLE"}]}`)
	if r.Hits[0].Path != "$.items[1].note" {
		t.Errorf("path = %s", r.Hits[0].Path)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "AKIA") {
		t.Fatal("report leaked the matched value")
	}
}

func TestLowConfidence(t *testing.T) {
	s := New()
	cases := map[string]string{
		"jwt":       `{"text":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}`,
		"password=": `{"text":"password = correcthorsebatterystaple"}`,
		"long hex":  `{"text":"` + strings.Repeat("ab", 24) + `"}`,
	}
	for name, js := range cases {
		if r := scan(t, s, js); r.Level != Low {
			t.Errorf("%s: level %s, want low", name, r.Level)
		}
	}
}

func TestCleanTextIsNone(t *testing.T) {
	s := New()
	for _, js := range []string{
		`{"ticket_id":"OPS-42","status":"closed"}`,
		`{"channel":"#triage-internal","text":"Closed OPS-2. OPS-1 pending review."}`,
		`{"text":"The meeting is at 10:30 in room 4B, bring the Q3 numbers."}`,
	} {
		if r := scan(t, s, js); r.Level != None {
			t.Errorf("%s: level %s, hits %+v", js, r.Level, r.Hits)
		}
	}
}

// D-4: a redaction placeholder the governor issued, or a token id, found in
// outbound args is an active hit, the strongest level.
func TestActiveValues(t *testing.T) {
	s := New()
	s.AddActive("[redacted:tok_9f2a7c1e]", "redaction")
	s.AddActive("1134c512af4cab26466a830160b729a5", "token")
	r := scan(t, s, `{"text":"FYI the summary says [redacted:tok_9f2a7c1e], escalate"}`)
	if r.Level != Active || r.Hits[0].Rule != "active_redaction" {
		t.Fatalf("got %+v", r)
	}
	r = scan(t, s, `{"text":"replay this: 1134c512af4cab26466a830160b729a5"}`)
	if r.Level != Active {
		t.Fatalf("token id: got %+v", r)
	}
	// Short values are not registered (too easy to hit by accident).
	s.AddActive("abc", "redaction")
	if r := scan(t, s, `{"text":"abc"}`); r.Level != None {
		t.Fatal("short active value matched")
	}
}

// Strongest level wins when several hits are present.
func TestStrongestWins(t *testing.T) {
	s := New()
	s.AddActive("[redacted:tok_deadbeef]", "redaction")
	r := scan(t, s, `{"a":"password=correcthorsebattery","b":"AKIAIOSFODNN7EXAMPLE","c":"[redacted:tok_deadbeef]"}`)
	if r.Level != Active || len(r.Hits) != 3 {
		t.Fatalf("got %+v", r)
	}
}

func TestNonJSONStillScanned(t *testing.T) {
	s := New()
	if r := s.Scan([]byte("AKIAIOSFODNN7EXAMPLE")); r.Level != High {
		t.Fatalf("got %+v", r)
	}
}

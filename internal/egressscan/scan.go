package egressscan

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Level is the strongest hit found.
type Level string

const (
	None   Level = "none"
	Low    Level = "low"
	High   Level = "high"
	Active Level = "active"
)

// Hit is one finding. Value is never included.
type Hit struct {
	Level Level  `json:"level"`
	Rule  string `json:"rule"`
	Path  string `json:"path"` // JSON path of the offending field, e.g. $.text
}

// Report is the outcome of one scan.
type Report struct {
	Level Level `json:"level"`
	Hits  []Hit `json:"hits,omitempty"`
}

// rule is a named pattern at a level.
type rule struct {
	name  string
	level Level
	re    *regexp.Regexp
}

// High-confidence rules: distinctive prefixes or structures. Kept short on
// purpose; every rule here is one a reviewer can read and agree with.
var rules = []rule{
	{"aws_access_key", High, regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github_token", High, regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"slack_token", High, regexp.MustCompile(`\bxox[abprs]-[0-9A-Za-z-]{10,}\b`)},
	{"stripe_key", High, regexp.MustCompile(`\b[sr]k_(live|test)_[0-9a-zA-Z]{20,}\b`)},
	{"google_api_key", High, regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"private_key_block", High, regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"bearer_in_url", High, regexp.MustCompile(`(?i)[?&](access_token|token|api_key|apikey|secret)=[A-Za-z0-9._~-]{16,}`)},
	{"basic_auth_in_url", High, regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`)},

	// Low confidence: shapes that need a human to say what they are.
	{"jwt_like", Low, regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	{"keyword_assignment", Low, regexp.MustCompile(`(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['"]?[A-Za-z0-9/+=_.-]{12,}`)},
	{"long_hex", Low, regexp.MustCompile(`\b[0-9a-f]{40,}\b`)},
	{"long_base64", Low, regexp.MustCompile(`\b[A-Za-z0-9+/]{48,}={0,2}\b`)},
}

// Scanner holds the governor-issued values that count as active.
type Scanner struct {
	active map[string]string // value -> what it is ("redaction", "token")
}

// New returns an empty scanner. Add active values as the governor issues them.
func New() *Scanner { return &Scanner{active: map[string]string{}} }

// AddActive registers a value the governor issued. Any later outbound
// argument containing it is an active hit. kind is for the audit record.
func (s *Scanner) AddActive(value, kind string) {
	if len(value) >= 8 { // nothing shorter is worth matching
		s.active[value] = kind
	}
}

// Scan walks the JSON args and returns the strongest level with every hit.
func (s *Scanner) Scan(args json.RawMessage) Report {
	var v any
	if err := json.Unmarshal(args, &v); err != nil {
		// Not JSON: scan the raw bytes as one string.
		return s.finish(s.scanString(string(args), "$"))
	}
	return s.finish(s.walk(v, "$"))
}

func (s *Scanner) walk(v any, path string) []Hit {
	var hits []Hit
	switch t := v.(type) {
	case string:
		hits = append(hits, s.scanString(t, path)...)
	case map[string]any:
		for k, val := range t {
			hits = append(hits, s.walk(val, path+"."+k)...)
		}
	case []any:
		for i, val := range t {
			hits = append(hits, s.walk(val, path+"["+itoa(i)+"]")...)
		}
	}
	return hits
}

func (s *Scanner) scanString(str, path string) []Hit {
	var hits []Hit
	for val, kind := range s.active {
		if strings.Contains(str, val) {
			hits = append(hits, Hit{Active, "active_" + kind, path})
		}
	}
	for _, r := range rules {
		if r.re.MatchString(str) {
			hits = append(hits, Hit{r.level, r.name, path})
		}
	}
	return hits
}

func (s *Scanner) finish(hits []Hit) Report {
	rep := Report{Level: None, Hits: hits}
	for _, h := range hits {
		if rank(h.Level) > rank(rep.Level) {
			rep.Level = h.Level
		}
	}
	return rep
}

func rank(l Level) int {
	switch l {
	case Active:
		return 3
	case High:
		return 2
	case Low:
		return 1
	}
	return 0
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

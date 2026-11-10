package canon

import "testing"

func TestKeyOrderAndWhitespaceDoNotMatter(t *testing.T) {
	a := Hash([]byte(`{"b": 1, "a": "x"}`))
	b := Hash([]byte(`{"a":"x","b":1}`))
	if a != b {
		t.Fatal("same args, different hash")
	}
}

func TestValuesMatter(t *testing.T) {
	a := Hash([]byte(`{"n":1}`))
	b := Hash([]byte(`{"n":1.0}`))
	c := Hash([]byte(`{"n":2}`))
	if a == b || a == c {
		t.Fatal("different args, same hash")
	}
}

func TestStringField(t *testing.T) {
	raw := []byte(`{"ticket_id":"OPS-1","n":3}`)
	if StringField(raw, "ticket_id") != "OPS-1" {
		t.Fatal("string field")
	}
	if StringField(raw, "n") != "" || StringField(raw, "missing") != "" {
		t.Fatal("non-string or missing should be empty")
	}
}

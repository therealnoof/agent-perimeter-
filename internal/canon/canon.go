// Package canon produces the one canonical encoding of a JSON args object
// that every component hashes. The governor hashes args to put in the
// verdict record and the token; the executor hashes what it received to
// check the token's binding. If those two ever disagreed, every token would
// fail, so this lives in one place and is deliberately dull.
//
// Canonical form: encoding/json's Marshal of the decoded value, which sorts
// object keys and strips whitespace. Numbers are preserved as written
// (json.Number) so 1 and 1.0 hash differently, as they should: they are
// different arguments.
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Bytes returns the canonical encoding, or the input unchanged if it is not
// valid JSON (the schema layer has already rejected that case upstream).
func Bytes(raw []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

// Hash returns the hex SHA-256 of the canonical encoding.
func Hash(raw []byte) string {
	sum := sha256.Sum256(Bytes(raw))
	return hex.EncodeToString(sum[:])
}

// StringField returns args[field] if it is a JSON string, else "".
func StringField(raw []byte, field string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	var s string
	if json.Unmarshal(m[field], &s) != nil {
		return ""
	}
	return s
}

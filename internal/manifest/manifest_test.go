package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A minimal valid manifest used across the tests.
const goodManifest = `{
  "role": "test-role",
  "data_clearance": "internal",
  "max_delegation_depth": 0,
  "tools": [
    {
      "name": "echo",
      "kind": "structured",
      "direction": "inbound",
      "max_calls_per_task": 3,
      "args_schema": {"type": "object", "properties": {"msg": {"type": "string"}}, "required": ["msg"], "additionalProperties": false}
    }
  ]
}`

// writeSigned writes the manifest and a valid signature into dir and returns
// the manifest path and the public key that verifies it.
func writeSigned(t *testing.T, dir, content string) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "m.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, []byte(content))
	if err := os.WriteFile(path+".sig", []byte(hex.EncodeToString(sig)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

func TestLoadValid(t *testing.T) {
	path, pub := writeSigned(t, t.TempDir(), goodManifest)
	m, err := Load(path, pub)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m.Role != "test-role" {
		t.Errorf("role = %q, want test-role", m.Role)
	}
	if m.Tool("echo") == nil {
		t.Error("tool echo not found")
	}
	if m.Tool("missing") != nil {
		t.Error("unexpected tool 'missing'")
	}
}

// G-1: a single flipped byte in the manifest body must refuse to load.
func TestFlippedByteInBody(t *testing.T) {
	path, pub := writeSigned(t, t.TempDir(), goodManifest)
	raw, _ := os.ReadFile(path)
	raw[len(raw)/2] ^= 0x01 // flip one bit in the middle
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, pub)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

// G-1: a flipped byte in the signature itself must also refuse.
func TestFlippedByteInSignature(t *testing.T) {
	path, pub := writeSigned(t, t.TempDir(), goodManifest)
	sig, _ := os.ReadFile(path + ".sig")
	// Flip a hex character; pick one that stays valid hex.
	if sig[0] == 'a' {
		sig[0] = 'b'
	} else {
		sig[0] = 'a'
	}
	if err := os.WriteFile(path+".sig", sig, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, pub)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

// G-1: no signature file at all must refuse.
func TestMissingSignature(t *testing.T) {
	path, pub := writeSigned(t, t.TempDir(), goodManifest)
	os.Remove(path + ".sig")
	_, err := Load(path, pub)
	if !errors.Is(err, ErrNoSignature) {
		t.Fatalf("got %v, want ErrNoSignature", err)
	}
}

// A manifest signed by a different key must refuse.
func TestWrongKey(t *testing.T) {
	path, _ := writeSigned(t, t.TempDir(), goodManifest)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, err := Load(path, otherPub)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

// Strictness: a correctly signed manifest with a typo'd field is still invalid.
// A signature proves who wrote it, not that it is well-formed.
func TestUnknownFieldRejected(t *testing.T) {
	bad := `{"role":"r","data_clearance":"x","max_delegation_depth":0,"allowed_tools":["*"],"tools":[]}`
	path, pub := writeSigned(t, t.TempDir(), bad)
	_, err := Load(path, pub)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestBadKindRejected(t *testing.T) {
	bad := `{"role":"r","data_clearance":"x","max_delegation_depth":0,"tools":[{"name":"t","kind":"magic","direction":"inbound","args_schema":{}}]}`
	path, pub := writeSigned(t, t.TempDir(), bad)
	_, err := Load(path, pub)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestSensitivityFloorRange(t *testing.T) {
	bad := `{"role":"r","data_clearance":"x","max_delegation_depth":0,"tools":[{"name":"t","kind":"structured","direction":"outbound","sensitivity_floor":11,"args_schema":{}}]}`
	path, pub := writeSigned(t, t.TempDir(), bad)
	_, err := Load(path, pub)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

package tokens

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

func pair(t *testing.T) (*Minter, *Verifier, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return NewMinter(priv, 0), NewVerifier(pub), pub
}

const (
	tool = "jira_update"
	tgt  = "OPS-42"
	hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestRoundTrip(t *testing.T) {
	m, v, _ := pair(t)
	tok, jti, err := m.Mint(tool, tgt, hash, "t1")
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(tok, tool, tgt, hash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.JTI != jti || c.Tool != tool || c.TaskID != "t1" {
		t.Errorf("claims wrong: %+v", c)
	}
}

// C-1: a captured token replayed for a call with different arguments fails
// on the binding, before any replay check.
func TestReplayWithDifferentArgsFails(t *testing.T) {
	m, v, _ := pair(t)
	tok, _, _ := m.Mint(tool, tgt, hash, "t1")
	other := strings.Repeat("ff", 32)
	if _, err := v.Verify(tok, tool, tgt, other); !errors.Is(err, ErrBinding) {
		t.Fatalf("got %v, want ErrBinding", err)
	}
	if _, err := v.Verify(tok, "jira_read", tgt, hash); !errors.Is(err, ErrBinding) {
		t.Fatalf("different tool: got %v, want ErrBinding", err)
	}
	if _, err := v.Verify(tok, tool, "OPS-1", hash); !errors.Is(err, ErrBinding) {
		t.Fatalf("different target: got %v, want ErrBinding", err)
	}
}

// C-1: the same token presented twice for the same call is refused.
func TestSingleUse(t *testing.T) {
	m, v, _ := pair(t)
	tok, _, _ := m.Mint(tool, tgt, hash, "t1")
	if _, err := v.Verify(tok, tool, tgt, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok, tool, tgt, hash); !errors.Is(err, ErrReplay) {
		t.Fatalf("got %v, want ErrReplay", err)
	}
}

// C-1: expiry. Move the verifier's clock forward past TTL + skew.
func TestExpired(t *testing.T) {
	m, v, _ := pair(t)
	tok, _, _ := m.Mint(tool, tgt, hash, "t1")
	v.now = func() time.Time { return time.Now().Add(DefaultTTL + Skew + time.Second) }
	if _, err := v.Verify(tok, tool, tgt, hash); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

// A token signed by a governor the verifier does not trust is refused.
func TestUnknownGovernor(t *testing.T) {
	m, _, _ := pair(t)
	_, v2, _ := pair(t) // trusts a different key
	tok, _, _ := m.Mint(tool, tgt, hash, "t1")
	if _, err := v2.Verify(tok, tool, tgt, hash); !errors.Is(err, ErrUnknown) {
		t.Fatalf("got %v, want ErrUnknown", err)
	}
}

// Any change to the body invalidates the signature.
func TestTamperedBody(t *testing.T) {
	m, v, _ := pair(t)
	tok, _, _ := m.Mint(tool, tgt, hash, "t1")
	parts := strings.Split(tok, ".")
	// base64url: flipping a character changes the decoded body.
	b := []byte(parts[0])
	if b[10] == 'A' {
		b[10] = 'B'
	} else {
		b[10] = 'A'
	}
	bad := string(b) + "." + parts[1]
	_, err := v.Verify(bad, tool, tgt, hash)
	if !errors.Is(err, ErrSignature) && !errors.Is(err, ErrFormat) && !errors.Is(err, ErrUnknown) {
		t.Fatalf("got %v, want a rejection", err)
	}
}

func TestMalformed(t *testing.T) {
	_, v, _ := pair(t)
	for _, bad := range []string{"", "abc", "a.b.c", "!!!.!!!", "eyJ2IjoxfQ.AAAA"} {
		if _, err := v.Verify(bad, tool, tgt, hash); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The seen-set is pruned, so a long-running verifier does not grow forever.
func TestSeenSetPrunes(t *testing.T) {
	m, v, _ := pair(t)
	for i := 0; i < 100; i++ {
		tok, _, _ := m.Mint(tool, tgt, hash, "t")
		v.Verify(tok, tool, tgt, hash)
	}
	if len(v.seen) != 100 {
		t.Fatalf("seen = %d, want 100", len(v.seen))
	}
	v.now = func() time.Time { return time.Now().Add(time.Minute) }
	tok, _, _ := m.Mint(tool, tgt, hash, "t") // minted with real clock, so "expired" to v
	v.Verify(tok, tool, tgt, hash)            // triggers prune
	if len(v.seen) != 0 {
		t.Fatalf("seen = %d after prune, want 0", len(v.seen))
	}
}

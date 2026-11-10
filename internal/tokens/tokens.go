package tokens

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// DefaultTTL is how long a token is valid. Long enough to spawn a process
// and have it check in; short enough that a captured token is nearly useless.
const DefaultTTL = 5 * time.Second

// Skew is the clock slack allowed when checking expiry. Executors run on the
// same host as the governor, so this is generous.
const Skew = 2 * time.Second

// Claims is what the governor signs. Field order is fixed for stable encoding.
type Claims struct {
	Ver      int    `json:"v"`         // format version, 1
	Governor string `json:"gov"`       // hex SHA-256 fingerprint of the signing public key
	JTI      string `json:"jti"`       // unique id, 128 bits random
	Tool     string `json:"tool"`      // action
	Target   string `json:"target"`    // resource, or "-"
	ArgsHash string `json:"args_hash"` // hex SHA-256 of canonical args
	TaskID   string `json:"task_id"`
	IssuedAt int64  `json:"iat"` // unix seconds
	Expires  int64  `json:"exp"` // unix seconds
}

// Errors callers can test for.
var (
	ErrFormat    = errors.New("token: malformed")
	ErrSignature = errors.New("token: signature does not verify")
	ErrExpired   = errors.New("token: expired")
	ErrNotYet    = errors.New("token: not yet valid")
	ErrBinding   = errors.New("token: does not match this call")
	ErrReplay    = errors.New("token: already used")
	ErrUnknown   = errors.New("token: signed by an unknown governor")
)

// Fingerprint identifies a public key in claims and in trust lists.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// Minter signs tokens with one governor key.
type Minter struct {
	priv ed25519.PrivateKey
	fp   string
	ttl  time.Duration
	now  func() time.Time
}

// NewMinter wraps a private key. ttl <= 0 means DefaultTTL.
func NewMinter(priv ed25519.PrivateKey, ttl time.Duration) *Minter {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Minter{priv: priv, fp: Fingerprint(priv.Public().(ed25519.PublicKey)), ttl: ttl, now: time.Now}
}

// GenerateKey makes a fresh governor keypair. The governor does this at
// startup; the key lives for one governor run and is never written to disk
// except as the public half for executors and the sidecar to read.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Mint signs claims for one call and returns the token string and its JTI.
func (m *Minter) Mint(tool, target, argsHash, taskID string) (string, string, error) {
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", "", err
	}
	now := m.now()
	c := Claims{
		Ver: 1, Governor: m.fp, JTI: hex.EncodeToString(jti[:]),
		Tool: tool, Target: target, ArgsHash: argsHash, TaskID: taskID,
		IssuedAt: now.Unix(), Expires: now.Add(m.ttl).Unix(),
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", "", err
	}
	sig := ed25519.Sign(m.priv, body)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(body) + "." + enc.EncodeToString(sig), c.JTI, nil
}

// Verifier checks tokens against a set of trusted governor public keys and
// remembers recently seen JTIs to refuse replays. One Verifier per process.
type Verifier struct {
	keys map[string]ed25519.PublicKey // fingerprint -> key
	now  func() time.Time

	mu   sync.Mutex
	seen map[string]int64 // jti -> exp, pruned on each call
}

// NewVerifier trusts the given keys.
func NewVerifier(keys ...ed25519.PublicKey) *Verifier {
	v := &Verifier{keys: map[string]ed25519.PublicKey{}, now: time.Now, seen: map[string]int64{}}
	for _, k := range keys {
		v.keys[Fingerprint(k)] = k
	}
	return v
}

// Parse decodes and signature-checks a token without binding or replay
// checks. Use Verify for the full check; Parse is for logging a rejected
// token's claims without trusting them.
func (v *Verifier) Parse(tok string) (*Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return nil, ErrFormat
	}
	enc := base64.RawURLEncoding
	body, err := enc.DecodeString(parts[0])
	if err != nil {
		return nil, ErrFormat
	}
	sig, err := enc.DecodeString(parts[1])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrFormat
	}
	var c Claims
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || c.Ver != 1 {
		return nil, ErrFormat
	}
	pub, ok := v.keys[c.Governor]
	if !ok {
		return nil, ErrUnknown
	}
	if !ed25519.Verify(pub, body, sig) {
		return nil, ErrSignature
	}
	return &c, nil
}

// Verify does the whole check: signature, time window, binding to this
// call, and single use. tool/target/argsHash are what the caller is about
// to do; they must equal what the governor signed.
func (v *Verifier) Verify(tok, tool, target, argsHash string) (*Claims, error) {
	now := v.now()
	v.prune(now)

	c, err := v.Parse(tok)
	if err != nil {
		return nil, err
	}
	if now.After(time.Unix(c.Expires, 0).Add(Skew)) {
		return nil, ErrExpired
	}
	if now.Before(time.Unix(c.IssuedAt, 0).Add(-Skew)) {
		return nil, ErrNotYet
	}
	if c.Tool != tool || c.Target != target || c.ArgsHash != argsHash {
		return nil, fmt.Errorf("%w: token is for %s/%s/%s", ErrBinding, c.Tool, c.Target, c.ArgsHash[:8])
	}

	// Single use.
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, used := v.seen[c.JTI]; used {
		return nil, ErrReplay
	}
	v.seen[c.JTI] = c.Expires
	return c, nil
}

// prune drops seen entries that can no longer be replayed because they have
// expired. Runs on every Verify, whatever the outcome, so the set is bounded
// by the number of tokens minted per TTL window.
func (v *Verifier) prune(now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	cutoff := now.Unix() - int64(Skew.Seconds())
	for j, exp := range v.seen {
		if exp < cutoff {
			delete(v.seen, j)
		}
	}
}

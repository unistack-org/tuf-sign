package tuf

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// KeyTypeEd25519 is the only key type and scheme this package supports.
const (
	KeyTypeEd25519 = "ed25519"
	SchemeEd25519  = "ed25519"
	hashAlgoSHA256 = "sha256"
	hashAlgoSHA512 = "sha512"
	specVersion    = "1.0.0"
)

// KeyID is the hex-encoded sha256 of the canonical JSON key object.
func KeyID(canonicalKey []byte) string {
	sum := sha256.Sum256(canonicalKey)
	return hex.EncodeToString(sum[:])
}

// KeyFromPublic builds a TUF Key from an ed25519 public key.
func KeyFromPublic(pub ed25519.PublicKey) Key {
	return Key{
		KeyType: KeyTypeEd25519,
		Scheme:  SchemeEd25519,
		KeyVal:  KeyVal{Public: base64.StdEncoding.EncodeToString(pub)},
	}
}

// KeyIDOf returns the canonical key id of k.
func KeyIDOf(k Key) (string, error) {
	return k.KeyIDHex()
}

// PublicKey decodes the base64 public portion of k.
func (k Key) PublicKey() (ed25519.PublicKey, error) {
	if k.KeyType != KeyTypeEd25519 || k.Scheme != SchemeEd25519 {
		return nil, fmt.Errorf("tuf: unsupported key type %q/%q", k.KeyType, k.Scheme)
	}
	raw, err := base64.StdEncoding.DecodeString(k.KeyVal.Public)
	if err != nil {
		return nil, fmt.Errorf("tuf: key %q: bad base64 public key: %w", k.KeyID, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("tuf: key %q: bad public key size %d", k.KeyID, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// Sign signs the canonical JSON of meta with priv, replacing every
// existing signature on the envelope. The returned envelope carries a
// single Signature whose keyid is the canonical id of pub.
func Sign(env *Signed, meta Meta, priv ed25519.PrivateKey) error {
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	c, err := Canonicalize(raw)
	if err != nil {
		return err
	}
	env.Signed = c
	return SignRaw(env, priv)
}

// SignRaw adds a signature over env.Signed (the bytes are signed as
// stored; callers that build Signed by hand should put canonical JSON
// in env.Signed first).
func SignRaw(env *Signed, priv ed25519.PrivateKey) error {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("tuf: private key has no ed25519 public key")
	}
	k := KeyFromPublic(pub)
	id, err := k.KeyIDHex()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, env.Signed)
	env.Signatures = append(env.Signatures, Signature{
		KeyID: id,
		Sig:   base64.StdEncoding.EncodeToString(sig),
	})
	return nil
}

// SignCanonical canonicalises meta, signs it and returns the envelope.
func SignCanonical(meta any, privs ...ed25519.PrivateKey) (*Signed, error) {
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	c, err := Canonicalize(raw)
	if err != nil {
		return nil, err
	}
	env := &Signed{Signed: c}
	for _, p := range privs {
		if err := SignRaw(env, p); err != nil {
			return nil, err
		}
	}
	return env, nil
}

// Decode unmarshals env.Signed into a fresh Meta of the given role and
// checks that its "type" field matches.
func Decode(env *Signed, role string) (Meta, error) {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(env.Signed, &probe); err != nil {
		return nil, fmt.Errorf("tuf: decode signed: %w", err)
	}
	if probe.Type != role {
		return nil, fmt.Errorf("tuf: metadata type %q, expected %q", probe.Type, role)
	}
	var m Meta
	switch role {
	case RootRole:
		m = &Root{}
	case SnapshotRole:
		m = &Snapshot{}
	case TimestampRole:
		m = &Timestamp{}
	default:
		m = &Targets{}
	}
	if err := json.Unmarshal(env.Signed, m); err != nil {
		return nil, fmt.Errorf("tuf: decode %s: %w", role, err)
	}
	return m, nil
}

// VerifySignature checks env signatures against the key set and
// threshold; it returns the number of valid distinct signatures.
// Signatures with unknown keyids are ignored (they cannot satisfy the
// threshold). The bytes that are verified are env.Signed verbatim.
func VerifySignature(env *Signed, keys map[string]Key, threshold int) (int, error) {
	if threshold < 1 {
		return 0, fmt.Errorf("tuf: threshold must be >= 1")
	}
	seen := map[string]bool{}
	n := 0
	for _, s := range env.Signatures {
		if seen[s.KeyID] {
			continue
		}
		k, ok := keys[s.KeyID]
		if !ok {
			continue
		}
		pub, err := k.PublicKey()
		if err != nil {
			return n, err
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			return n, fmt.Errorf("tuf: signature of %q: bad base64: %w", s.KeyID, err)
		}
		if !ed25519.Verify(pub, env.Signed, sig) {
			return n, fmt.Errorf("tuf: signature of %q is invalid", s.KeyID)
		}
		seen[s.KeyID] = true
		n++
	}
	if n < threshold {
		return n, fmt.Errorf("tuf: threshold not met: %d valid signatures, need %d", n, threshold)
	}
	return n, nil
}

// SignedBytes returns env.Signed, canonicalised (idempotent). Verifiers
// canonicalise before checking so a producer that stored pretty JSON
// still passes.
func (env *Signed) SignedBytes() ([]byte, error) {
	return Canonicalize(env.Signed)
}

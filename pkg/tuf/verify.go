package tuf

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"time"
)

// Hash returns the hex digest of data under algo ("sha256" | "sha512").
func Hash(algo string, data []byte) (string, error) {
	var h hash.Hash
	switch algo {
	case hashAlgoSHA256:
		h = sha256.New()
	case hashAlgoSHA512:
		h = sha512.New()
	default:
		return "", fmt.Errorf("tuf: unsupported hash algorithm %q", algo)
	}
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CheckHashes verifies data against the pinned hash set. Every present
// algorithm must match; at least one hash is required.
func (h Hashes) Check(data []byte) error {
	if len(h) == 0 {
		return fmt.Errorf("tuf: no pinned hashes")
	}
	for algo, want := range h {
		got, err := Hash(algo, data)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("tuf: hash mismatch (%s): got %s, want %s", algo, got, want)
		}
	}
	return nil
}

// Verify decodes env as the given role, canonicalises the signed
// bytes, checks signatures against keys/threshold and expiry against
// now. It returns the decoded metadata.
func Verify(env *Signed, role string, keys map[string]Key, threshold int, now time.Time) (Meta, error) {
	canon, err := env.SignedBytes()
	if err != nil {
		return nil, err
	}
	env.Signed = canon
	meta, err := Decode(env, role)
	if err != nil {
		return nil, err
	}
	if threshold > 0 {
		if _, err := VerifySignature(env, keys, threshold); err != nil {
			return nil, fmt.Errorf("tuf: %s: %w", role, err)
		}
	}
	if err := CheckExpiry(meta, now); err != nil {
		return nil, err
	}
	return meta, nil
}

// CheckExpiry fails when meta is expired at now (freeze check for a
// single file's own expiry).
func CheckExpiry(meta Meta, now time.Time) error {
	if !now.Before(meta.MetaExpires()) {
		return fmt.Errorf("tuf: %s expired at %s", meta.Role(), meta.MetaExpires().Format(time.RFC3339))
	}
	return nil
}

// CheckRollback enforces the rollback rule: the new metadata version
// must not be lower than the last known one.
func CheckRollback(meta Meta, known FileMeta) error {
	if meta.MetaVersion() < known.Version {
		return fmt.Errorf("tuf: %s rollback: new version %d < known %d",
			meta.Role(), meta.MetaVersion(), known.Version)
	}
	return nil
}

// CheckFreeze enforces the freeze rule: a re-signing of a role must
// not shorten its expiry (a stale file replayed by an attacker expires
// no later than the newest copy we have seen).
func CheckFreeze(meta Meta, prevExpires time.Time) error {
	if prevExpires.IsZero() {
		return nil
	}
	if meta.MetaExpires().Before(prevExpires) {
		return fmt.Errorf("tuf: %s freeze: new expiry %s earlier than known %s",
			meta.Role(), meta.MetaExpires().Format(time.RFC3339), prevExpires.Format(time.RFC3339))
	}
	return nil
}

// CheckMixAndMatch enforces that the metadata bytes match what the
// (already trusted) parent pinned: version, hash and length.
func CheckMixAndMatch(env *Signed, fm FileMeta) error {
	var hdr struct {
		Type    string `json:"type"`
		Version int64  `json:"version"`
	}
	if err := json.Unmarshal(env.Signed, &hdr); err != nil {
		return err
	}
	if fm.Version != 0 && hdr.Version != fm.Version {
		return fmt.Errorf("tuf: mix-and-match: %s version %d != pinned %d", hdr.Type, hdr.Version, fm.Version)
	}
	if len(fm.Hashes) > 0 {
		if err := fm.Hashes.Check(env.Signed); err != nil {
			return fmt.Errorf("tuf: mix-and-match: %s: %w", hdr.Type, err)
		}
	}
	if fm.Length != 0 && int64(len(env.Signed)) != fm.Length {
		return fmt.Errorf("tuf: mix-and-match: %s length %d != pinned %d", hdr.Type, len(env.Signed), fm.Length)
	}
	return nil
}

package tuf

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

func TestSignVerifyRoundtrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	k := KeyFromPublic(pub)
	id, err := k.KeyIDHex()
	if err != nil {
		t.Fatal(err)
	}

	ts := &Timestamp{
		Type:    TimestampRole,
		Version: 7,
		Expires: testClock,
		Meta:    map[string]FileMeta{},
	}
	env, err := SignCanonical(ts, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Signed bytes must be canonical.
	if !bytes.Equal(env.Signed, mustCanonical(t, env.Signed)) {
		t.Fatal("SignCanonical did not canonicalize")
	}
	keys := map[string]Key{id: k}
	n, err := VerifySignature(env, keys, 1)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if n != 1 {
		t.Fatalf("valid signatures = %d, want 1", n)
	}
	meta, err := Verify(env, TimestampRole, keys, 1, testClock.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if meta.MetaVersion() != 7 {
		t.Fatalf("version = %d, want 7", meta.MetaVersion())
	}
}

func TestVerifyTamperedByte(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	k := KeyFromPublic(priv.Public().(ed25519.PublicKey))
	id, _ := k.KeyIDHex()
	ts := &Timestamp{Type: TimestampRole, Version: 1, Expires: testClock, Meta: map[string]FileMeta{}}
	env, err := SignCanonical(ts, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Flip the version inside the signed object; bytes change, sig breaks.
	mutated := *env
	var m map[string]any
	if err := json.Unmarshal(env.Signed, &m); err != nil {
		t.Fatal(err)
	}
	m["version"] = json.Number("2")
	raw, err := MarshalCanonical(m)
	if err != nil {
		t.Fatal(err)
	}
	mutated.Signed = raw
	keys := map[string]Key{id: k}
	if _, err := VerifySignature(&mutated, keys, 1); err == nil {
		t.Fatal("tampered signed object accepted")
	}
}

func TestVerifyThreshold2of3(t *testing.T) {
	ks := make([]ed25519.PrivateKey, 3)
	keys := map[string]Key{}
	for i := range ks {
		_, priv, _ := ed25519.GenerateKey(nil)
		ks[i] = priv
		k := KeyFromPublic(priv.Public().(ed25519.PublicKey))
		id, _ := k.KeyIDHex()
		k.KeyID = id
		keys[id] = k
	}
	ts := &Timestamp{Type: TimestampRole, Version: 1, Expires: testClock, Meta: map[string]FileMeta{}}

	env, err := SignCanonical(ts, ks[0], ks[2])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignature(env, keys, 2); err != nil {
		t.Fatalf("2-of-3 with 2 sigs: %v", err)
	}
	if _, err := VerifySignature(env, keys, 3); err == nil {
		t.Fatal("threshold 3 accepted with 2 sigs")
	}
	// Duplicate signature by the same key does not count twice.
	env2, err := SignCanonical(ts, ks[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRaw(env2, ks[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignature(env2, keys, 2); err == nil {
		t.Fatal("duplicate keyid signatures satisfied threshold 2")
	}
}

func TestVerifyUnknownKeyidIgnored(t *testing.T) {
	_, signPriv, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	k := KeyFromPublic(signPriv.Public().(ed25519.PublicKey))
	id, _ := k.KeyIDHex()
	ok := &Timestamp{Type: TimestampRole, Version: 1, Expires: testClock, Meta: map[string]FileMeta{}}
	env, err := SignCanonical(ok, signPriv, otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]Key{id: k}
	// extra signature from a key not in the role key set is ignored,
	// the valid one still counts.
	if _, err := VerifySignature(env, keys, 1); err != nil {
		t.Fatalf("foreign signature broke verification: %v", err)
	}
}

func TestKeyIDDeterministic(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	k1 := KeyFromPublic(pub)
	k2 := KeyFromPublic(pub)
	id1, err := k1.KeyIDHex()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := k2.KeyIDHex()
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("key id not deterministic: %s vs %s", id1, id2)
	}
	// KeyIDHex must not depend on the KeyID field itself.
	k3 := k1
	k3.KeyID = "deadbeef"
	id3, err := k3.KeyIDHex()
	if err != nil {
		t.Fatal(err)
	}
	if id3 != id1 {
		t.Fatalf("KeyIDHex influenced by embedded id: %s vs %s", id3, id1)
	}
	_ = priv
}

func mustCanonical(t *testing.T, raw []byte) []byte {
	t.Helper()
	c, err := Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

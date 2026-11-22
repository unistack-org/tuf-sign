package tuf

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestChainHappyPath(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	artifact := []byte("cell-binary-v1.2.3")
	tg := makeTarget(t, artifact, Custom{Version: "1.2.3"})
	p.PublishTargets(map[string]Target{"v1.2.3/cell-linux-amd64": tg}, nil, nil)

	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := u.Update(p.fetcher())
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.VerifyTarget("", "v1.2.3/cell-linux-amd64", artifact); err != nil {
		t.Fatalf("VerifyTarget: %v", err)
	}
	if err := chain.VerifyTarget("", "v1.2.3/cell-linux-amd64", []byte("evil")); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	// Second update with the same state must also pass.
	if _, err := u.Update(p.fetcher()); err != nil {
		t.Fatalf("second update: %v", err)
	}
}

func TestChainExpiredTimestamp(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	p.PublishTargets(nil, nil, nil)
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	// Re-sign timestamp as expired (before "now").
	env := decodeEnv(t, p.files[TimestampRole])
	var m map[string]any
	mustJSON(t, env.Signed, &m)
	m["expires"] = testClock.Add(-time.Minute).Format(time.RFC3339)
	env.Signed = mustMarshalCanonical(t, m)
	p.files[TimestampRole] = resign(t, env, keys.Ts)
	if _, err := u.Update(p.fetcher()); err == nil {
		t.Fatal("expired timestamp accepted")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %v, want expiry", err)
	}
}

func TestChainRollbackTimestamp(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	p.PublishTargets(nil, nil, nil)
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Update(p.fetcher()); err != nil {
		t.Fatal(err)
	}
	// Serve an older (validly signed, lower-version) timestamp.
	env := decodeEnv(t, p.files[TimestampRole])
	var m map[string]any
	mustJSON(t, env.Signed, &m)
	m["version"] = json.Number("0")
	env.Signed = mustMarshalCanonical(t, m)
	p.files[TimestampRole] = resign(t, env, keys.Ts)
	if _, err := u.Update(p.fetcher()); err == nil {
		t.Fatal("rolled-back timestamp accepted")
	} else if !strings.Contains(err.Error(), "rollback") && !strings.Contains(err.Error(), "mix-and-match") {
		t.Fatalf("error = %v, want rollback/mix-match", err)
	}
}

func TestChainRollbackSnapshotVersion(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	p.PublishTargets(nil, nil, nil)
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Update(p.fetcher()); err != nil {
		t.Fatal(err)
	}
	// Old snapshot: version 1 with its original content, re-pinned in a
	// fresh timestamp so the timestamp check passes and snapshot
	// rollback fires.
	oldSnap := p.files[SnapshotRole]
	oldEnv := decodeEnv(t, oldSnap)
	var sm map[string]any
	mustJSON(t, oldEnv.Signed, &sm)
	if v, _ := sm["version"].(json.Number); v.String() != "1" {
		if f, ok := sm["version"].(float64); !ok || f != 1 {
			t.Fatalf("precondition: snapshot version = %v", sm["version"])
		}
	}
	p.PublishTargets(nil, nil, nil) // snapshot v2, timestamp v2
	if _, err := u.Update(p.fetcher()); err != nil {
		t.Fatal(err)
	}
	// Now serve old snapshot (v1) with a fresh timestamp pinning it.
	freshTs := decodeEnv(t, p.files[TimestampRole])
	pin, err := signedFileMeta(oldEnv)
	if err != nil {
		t.Fatal(err)
	}
	var tm map[string]any
	mustJSON(t, freshTs.Signed, &tm)
	meta := tm["meta"].(map[string]any)
	meta["snapshot"] = jsonMarshalValue(t, pin)
	freshTs.Signed = mustMarshalCanonical(t, tm)
	files := fetcherMap{}
	for k, v := range p.files {
		files[k] = v
	}
	files[SnapshotRole] = oldSnap
	files[TimestampRole] = resign(t, freshTs, keys.Ts)
	if _, err := u.Update(files); err == nil {
		t.Fatal("snapshot rollback accepted")
	} else if !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("error = %v, want rollback", err)
	}
}

func TestChainFreezeSnapshotExpiry(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	p.PublishTargets(nil, nil, nil)
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Update(p.fetcher()); err != nil {
		t.Fatal(err)
	}
	// New snapshot: higher version, EARLIER expiry (stale re-sign attack).
	env := decodeEnv(t, p.files[SnapshotRole])
	var m map[string]any
	mustJSON(t, env.Signed, &m)
	m["version"] = json.Number("99")
	m["expires"] = testClock.Add(time.Minute).Format(time.RFC3339)
	env.Signed = mustMarshalCanonical(t, m)
	newSnap := resign(t, env, keys.Snap)
	// Fresh timestamp pins the frozen-looking snapshot.
	freshTs := decodeEnv(t, p.files[TimestampRole])
	pin, err := signedFileMeta(env)
	if err != nil {
		t.Fatal(err)
	}
	var tm map[string]any
	mustJSON(t, freshTs.Signed, &tm)
	tm["meta"].(map[string]any)["snapshot"] = jsonMarshalValue(t, pin)
	freshTs.Signed = mustMarshalCanonical(t, tm)
	files := fetcherMap{}
	for k, v := range p.files {
		files[k] = v
	}
	files[SnapshotRole] = newSnap
	files[TimestampRole] = resign(t, freshTs, keys.Ts)
	if _, err := u.Update(files); err == nil {
		t.Fatal("freeze violation accepted")
	} else if !strings.Contains(err.Error(), "freeze") {
		t.Fatalf("error = %v, want freeze", err)
	}
}

func TestChainMixAndMatch(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	good := []byte("release A")
	tg := makeTarget(t, good, Custom{Version: "1.0.0"})
	p.PublishTargets(map[string]Target{"v1.0.0/cell": tg}, nil, nil)
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	// After publishing, swap targets.json content for a different
	// (validly signed, same version) set — timestamp/snapshot pins
	// the original bytes, so mix-and-match must fire.
	evilEnv := decodeEnv(t, p.files[TargetsRole])
	var em map[string]any
	mustJSON(t, evilEnv.Signed, &em)
	targets := em["targets"].(map[string]any)
	bad := makeTarget(t, []byte("release B evil"), Custom{Version: "1.0.0"})
	targets["v1.0.0/cell"] = jsonMarshalValue(t, bad)
	evilEnv.Signed = mustMarshalCanonical(t, em)
	p.files[TargetsRole] = resign(t, evilEnv, keys.Tg)
	if _, err := u.Update(p.fetcher()); err == nil {
		t.Fatal("mix-and-match accepted")
	} else if !strings.Contains(err.Error(), "mix-and-match") {
		t.Fatalf("error = %v, want mix-and-match", err)
	}
}

func TestChainThreshold2Of3Root(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	p.PublishTargets(nil, nil, nil)
	// Rotate the root role to 2-of-3 in one step is not allowed
	// (stepwise); build the root with 3 root keys, threshold 2 from v1.
	_, r1, _ := genKey()
	_, r2, _ := genKey()
	_, r3, _ := genKey()
	ids := []string{}
	root := &Root{
		Type:        RootRole,
		Version:     1,
		SpecVersion: "1.0.0",
		Expires:     testClock.AddDate(1, 0, 0),
		Keys:        map[string]Key{},
		Roles:       map[string]Role{},
	}
	for _, pk := range []ed25519.PrivateKey{r1, r2, r3} {
		id, k := keyEntry(pk)
		root.Keys[id] = k
		ids = append(ids, id)
	}
	snapID, snapK := keyEntry(keys.Snap)
	tsID, tsK := keyEntry(keys.Ts)
	tgID, tgK := keyEntry(keys.Tg)
	root.Keys[snapID] = snapK
	root.Keys[tsID] = tsK
	root.Keys[tgID] = tgK
	root.Roles[RootRole] = Role{KeyIDs: ids, Threshold: 2}
	root.Roles[SnapshotRole] = Role{KeyIDs: []string{snapID}, Threshold: 1}
	root.Roles[TimestampRole] = Role{KeyIDs: []string{tsID}, Threshold: 1}
	root.Roles[TargetsRole] = Role{KeyIDs: []string{tgID}, Threshold: 1}

	env, err := SignCanonical(root, r1, r2)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewUpdater(raw, mustNow); err != nil {
		t.Fatalf("2-of-3 root rejected: %v", err)
	}
	env1, err := SignCanonical(root, r1)
	if err != nil {
		t.Fatal(err)
	}
	raw1, _ := json.Marshal(env1)
	if _, err := NewUpdater(raw1, mustNow); err == nil {
		t.Fatal("1 signature satisfied threshold 2")
	}
}

func TestChainForeignKeyNotInRoot(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	p.PublishTargets(nil, nil, nil)
	// Attacker re-signs timestamp with a foreign key and lists that
	// key in the timestamp role of a tampered root — root signature
	// breaks; simpler vector: attacker signs timestamp with foreign
	// key only, root unchanged.
	env := decodeEnv(t, p.files[TimestampRole])
	env.Signatures = nil
	if err := SignRaw(env, keys.Extra); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	p.files[TimestampRole] = raw
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Update(p.fetcher()); err == nil {
		t.Fatal("timestamp signed by foreign key accepted")
	} else if !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("error = %v, want threshold failure", err)
	}
}

func TestRootRotation(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	p.PublishTargets(nil, nil, nil)
	rootV1 := append([]byte(nil), p.files[RootRole]...)
	u, err := NewUpdater(rootV1, mustNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Update(p.fetcher()); err != nil {
		t.Fatal(err)
	}

	// Build root v2 with a NEW root key, signed by BOTH v1 and v2 root keys.
	_, newRootPriv, _ := genKey()
	oldRootPriv := keys.Root
	env := decodeEnv(t, p.files[RootRole])
	var m map[string]any
	mustJSON(t, env.Signed, &m)
	m["version"] = json.Number("2")
	newID, newK := keyEntry(newRootPriv)
	keysObj := m["keys"].(map[string]any)
	nk, err := json.Marshal(newK)
	if err != nil {
		t.Fatal(err)
	}
	keysObj[newID] = jsonRawValue(nk)
	rolesObj := m["roles"].(map[string]any)
	rolesObj["root"] = jsonMarshalValue(t, Role{KeyIDs: []string{newID}, Threshold: 1})
	env.Signed = mustMarshalCanonical(t, m)
	// Signed by new root key only → must be rejected by updater.
	p.files[RootRole] = resign(t, env, newRootPriv)
	if _, err := u.Update(p.fetcher()); err == nil {
		t.Fatal("rotation signed only by new key accepted")
	}
	// Signed by both old and new → accepted.
	p.files[RootRole] = resign(t, env, oldRootPriv, newRootPriv)
	chain, err := u.Update(p.fetcher())
	if err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if chain.Root.Version != 2 {
		t.Fatalf("root version = %d, want 2", chain.Root.Version)
	}
	// Rollback of root: serving v1 again after rotation must fail.
	if _, err := u.Update(p.fetcher()); err != nil {
		t.Fatal(err)
	}
	p.files[RootRole] = rootV1
	if _, err := u.Update(p.fetcher()); err == nil {
		t.Fatal("root rollback accepted after rotation")
	}
}

func TestChannelDelegation(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	artifact := []byte("nightly-build")
	tg := makeTarget(t, artifact, Custom{Version: "0.9.0"})
	chanKeys := map[string]ed25519.PrivateKey{
		ChannelDevelop: keys.Dev,
		ChannelStable:  keys.Stab,
	}
	p.PublishTargets(
		map[string]Target{},
		map[string]map[string]Target{
			ChannelDevelop: {"v0.9.0/cell-linux-amd64": tg},
			ChannelStable:  {},
		},
		chanKeys,
	)
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := u.Update(p.fetcher())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := chain.Target(ChannelDevelop, "v0.9.0/cell-linux-amd64"); !ok {
		t.Fatal("develop target missing")
	}
	if err := chain.VerifyTarget(ChannelDevelop, "v0.9.0/cell-linux-amd64", artifact); err != nil {
		t.Fatal(err)
	}
	// Not promoted: stable has no target, promotion cross-check fails.
	if ch, ok := chain.PromotedTo(ChannelDevelop, "v0.9.0/cell-linux-amd64"); ok {
		t.Fatalf("unexpectedly promoted to %q", ch)
	}
	if err := CheckPromotion(chain, ChannelDevelop, ChannelStable, "v0.9.0/cell-linux-amd64"); err == nil {
		t.Fatal("promotion check passed with target absent from stable")
	}
	// Channel signed with the WRONG channel key must be rejected.
	env := decodeEnv(t, p.files[ChannelRolePrefix+ChannelDevelop])
	p.files[ChannelRolePrefix+ChannelDevelop] = resign(t, env, keys.Test)
	if _, err := u.Update(p.fetcher()); err == nil {
		t.Fatal("channel signed with foreign key accepted")
	}
}

func TestChannelPromoteSameHash(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	artifact := []byte("release-candidate")
	tg := makeTarget(t, artifact, Custom{Version: "1.1.0"})
	chanKeys := map[string]ed25519.PrivateKey{
		ChannelDevelop: keys.Dev,
		ChannelStable:  keys.Stab,
	}
	p.PublishTargets(
		map[string]Target{},
		map[string]map[string]Target{
			ChannelDevelop: {"v1.1.0/cell-linux-amd64": tg},
			ChannelStable:  {},
		},
		chanKeys,
	)
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Update(p.fetcher()); err != nil {
		t.Fatal(err)
	}
	// Promote: identical target (same hash) into stable.
	p.PublishTargets(
		map[string]Target{},
		map[string]map[string]Target{
			ChannelDevelop: {"v1.1.0/cell-linux-amd64": tg},
			ChannelStable:  {"v1.1.0/cell-linux-amd64": tg},
		},
		chanKeys,
	)
	chain, err := u.Update(p.fetcher())
	if err != nil {
		t.Fatal(err)
	}
	// Same artefact verifies under BOTH channels with one download.
	for _, ch := range []string{ChannelDevelop, ChannelStable} {
		if err := chain.VerifyTarget(ch, "v1.1.0/cell-linux-amd64", artifact); err != nil {
			t.Fatalf("channel %s: %v", ch, err)
		}
	}
	if ch, ok := chain.PromotedTo(ChannelDevelop, "v1.1.0/cell-linux-amd64"); !ok || ch != ChannelStable {
		t.Fatalf("PromotedTo = %q,%v", ch, ok)
	}
	if err := CheckPromotion(chain, ChannelDevelop, ChannelStable, "v1.1.0/cell-linux-amd64"); err != nil {
		t.Fatalf("CheckPromotion: %v", err)
	}
}

func TestChannelPromoteHashMismatch(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	dev := makeTarget(t, []byte("good build"), Custom{Version: "1.2.0"})
	evil := makeTarget(t, []byte("evil build"), Custom{Version: "1.2.0"})
	chanKeys := map[string]ed25519.PrivateKey{
		ChannelDevelop: keys.Dev,
		ChannelStable:  keys.Stab,
	}
	p.PublishTargets(
		map[string]Target{},
		map[string]map[string]Target{
			ChannelDevelop: {"v1.2.0/cell": dev},
			ChannelStable:  {"v1.2.0/cell": evil},
		},
		chanKeys,
	)
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := u.Update(p.fetcher())
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPromotion(chain, ChannelDevelop, ChannelStable, "v1.2.0/cell"); err == nil {
		t.Fatal("promotion accepted with different hashes")
	}
}

// decodeEnv unmarshals a role file into a Signed envelope.
func decodeEnv(t *testing.T, raw []byte) *Signed {
	t.Helper()
	env, err := decodeSigned(raw)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func mustJSON(t *testing.T, raw []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func mustMarshalCanonical(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func jsonMarshalValue(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func jsonRawValue(raw []byte) json.RawMessage { return raw }

func genKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// signedFileMeta computes the FileMeta pin for a signed envelope.
func signedFileMeta(env *Signed) (FileMeta, error) {
	canon, err := env.SignedBytes()
	if err != nil {
		return FileMeta{}, err
	}
	var hdr struct {
		Version int64     `json:"version"`
		Expires time.Time `json:"expires"`
	}
	if err := json.Unmarshal(canon, &hdr); err != nil {
		return FileMeta{}, err
	}
	exp := hdr.Expires
	return FileMeta{
		Version: hdr.Version,
		Expires: &exp,
		Hashes:  Hashes{hashAlgoSHA256: sha256Hex(canon)},
		Length:  int64(len(canon)),
	}, nil
}

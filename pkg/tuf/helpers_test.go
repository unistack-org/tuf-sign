package tuf

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// testClock is the fixed "now" used across chain tests.
var testClock = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func mustNow() time.Time { return testClock }

type testKeys struct {
	t     *testing.T
	Root  ed25519.PrivateKey
	Snap  ed25519.PrivateKey
	Ts    ed25519.PrivateKey
	Tg    ed25519.PrivateKey
	Dev   ed25519.PrivateKey
	Test  ed25519.PrivateKey
	Stab  ed25519.PrivateKey
	Extra ed25519.PrivateKey // foreign key, never registered
}

func newTestKeys(t *testing.T) *testKeys {
	t.Helper()
	gen := func() ed25519.PrivateKey {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		return priv
	}
	return &testKeys{
		t:     t,
		Root:  gen(),
		Snap:  gen(),
		Ts:    gen(),
		Tg:    gen(),
		Dev:   gen(),
		Test:  gen(),
		Stab:  gen(),
		Extra: gen(),
	}
}

func keyEntry(priv ed25519.PrivateKey) (string, Key) {
	k := KeyFromPublic(priv.Public().(ed25519.PublicKey))
	id, err := k.KeyIDHex()
	if err != nil {
		panic(err)
	}
	k.KeyID = id
	return id, k
}

// publisher builds a full coherent metadata set the way the real
// producer will (all roles signed canonical, snapshot pins everything,
// timestamp pins snapshot).
type publisher struct {
	t       *testing.T
	keys    *testKeys
	rootKID string
	files   map[string][]byte // role → raw file bytes
	version map[string]int64
}

func newPublisher(t *testing.T, keys *testKeys) *publisher {
	t.Helper()
	p := &publisher{
		t:       t,
		keys:    keys,
		files:   map[string][]byte{},
		version: map[string]int64{},
	}
	p.rebuildRoot(keys)
	return p
}

func (p *publisher) rebuildRoot(keys *testKeys) {
	p.rootKID, _ = func() (string, Key) { return keyEntry(keys.Root) }()
	rootID, rootKey := keyEntry(keys.Root)
	snapID, snapKey := keyEntry(keys.Snap)
	tsID, tsKey := keyEntry(keys.Ts)
	tgID, tgKey := keyEntry(keys.Tg)
	p.rootKID = rootID
	root := &Root{
		Type:        RootRole,
		Version:     p.version[RootRole] + 1,
		SpecVersion: "1.0.0",
		Expires:     testClock.AddDate(1, 0, 0),
		Keys: map[string]Key{
			rootID: rootKey, snapID: snapKey, tsID: tsKey, tgID: tgKey,
		},
		Roles: map[string]Role{
			RootRole:      {KeyIDs: []string{rootID}, Threshold: 1},
			SnapshotRole:  {KeyIDs: []string{snapID}, Threshold: 1},
			TimestampRole: {KeyIDs: []string{tsID}, Threshold: 1},
			TargetsRole:   {KeyIDs: []string{tgID}, Threshold: 1},
		},
	}
	p.version[RootRole] = root.Version
	p.signInto(RootRole, root, keys.Root)
}

// sign canonical-signs meta with privs and stores the file.
func (p *publisher) signInto(role string, meta any, privs ...ed25519.PrivateKey) {
	env, err := SignCanonical(meta, privs...)
	if err != nil {
		p.t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		p.t.Fatal(err)
	}
	p.files[role] = raw
}

// PublishTargets writes top-level targets (with channel delegations)
// and the given channel role files, then refreshes snapshot+timestamp.
func (p *publisher) PublishTargets(targets map[string]Target, channels map[string]map[string]Target, chanKeys map[string]ed25519.PrivateKey) {
	tgID, tgKey := keyEntry(p.keys.Tg)
	tg := &Targets{
		Type:        TargetsRole,
		Version:     p.version[TargetsRole] + 1,
		Expires:     testClock.AddDate(0, 6, 0),
		Targets:     targets,
		Keys:        map[string]Key{tgID: tgKey},
		Delegations: &Delegations{Keys: map[string]Key{}},
	}
	p.version[TargetsRole] = tg.Version
	var chanVersions map[string]int64
	if len(channels) > 0 {
		for name, ctargets := range channels {
			role := ChannelRolePrefix + name
			ck, cke := keyEntry(chanKeys[name])
			tg.Delegations.Keys[ck] = cke
			tg.Delegations.Roles = append(tg.Delegations.Roles, DelegatedRole{
				Name:      role,
				Paths:     []string{"*"},
				KeyIDs:    []string{ck},
				Threshold: 1,
			})
			cver := p.version[role] + 1
			if chanVersions == nil {
				chanVersions = map[string]int64{}
			}
			chanVersions[role] = cver
			ct := &Targets{
				Type:        TargetsRole,
				Version:     cver,
				Expires:     testClock.AddDate(0, 3, 0),
				Targets:     ctargets,
				Keys:        map[string]Key{ck: cke},
				Delegations: nil,
			}
			p.version[role] = cver
			p.signInto(role, ct, chanKeys[name])
		}
	} else {
		tg.Delegations = nil
	}
	p.signInto(TargetsRole, tg, p.keys.Tg)
	p.RefreshSnapshotTimestamp()
}

// RefreshSnapshotTimestamp re-pins every published role file.
func (p *publisher) RefreshSnapshotTimestamp() {
	pin := func(role string) FileMeta {
		raw := p.files[role]
		env := &Signed{}
		if err := json.Unmarshal(raw, env); err != nil {
			p.t.Fatal(err)
		}
		canon, err := env.SignedBytes()
		if err != nil {
			p.t.Fatal(err)
		}
		var hdr struct {
			Version int64     `json:"version"`
			Expires time.Time `json:"expires"`
		}
		if err := json.Unmarshal(canon, &hdr); err != nil {
			p.t.Fatal(err)
		}
		exp := hdr.Expires
		return FileMeta{
			Version: hdr.Version,
			Expires: &exp,
			Hashes:  Hashes{hashAlgoSHA256: sha256Hex(canon)},
			Length:  int64(len(canon)),
		}
	}
	snap := &Snapshot{
		Type:    SnapshotRole,
		Version: p.version[SnapshotRole] + 1,
		Expires: testClock.AddDate(0, 1, 0),
		Meta:    map[string]FileMeta{},
	}
	p.version[SnapshotRole] = snap.Version
	snap.Meta[TargetsRole] = pin(TargetsRole)
	for role := range p.files {
		if len(role) > len(ChannelRolePrefix) && role[:len(ChannelRolePrefix)] == ChannelRolePrefix {
			snap.Meta[role] = pin(role)
		}
	}
	p.signInto(SnapshotRole, snap, p.keys.Snap)

	ts := &Timestamp{
		Type:    TimestampRole,
		Version: p.version[TimestampRole] + 1,
		Expires: testClock.AddDate(0, 0, 1),
		Meta: map[string]FileMeta{
			SnapshotRole: pin(SnapshotRole),
		},
	}
	p.version[TimestampRole] = ts.Version
	p.signInto(TimestampRole, ts, p.keys.Ts)
}

func (p *publisher) fetcher() Fetcher {
	return fetcherMap(p.files)
}

type fetcherMap map[string][]byte

func (f fetcherMap) Fetch(role string) ([]byte, error) {
	data, ok := f[role]
	if !ok {
		return nil, fmt.Errorf("no role %q", role)
	}
	return data, nil
}

// makeTarget hashes data and builds the target entry with custom.
func makeTarget(t *testing.T, data []byte, c Custom) Target {
	t.Helper()
	raw, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return Target{
		Length: int64(len(data)),
		Hashes: Hashes{hashAlgoSHA256: sha256Hex(data)},
		Custom: raw,
	}
}

// resign signs a (possibly mutated) env with priv, replacing all signatures.
func resign(t *testing.T, env *Signed, privs ...ed25519.PrivateKey) []byte {
	t.Helper()
	env.Signatures = nil
	for _, priv := range privs {
		if err := SignRaw(env, priv); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

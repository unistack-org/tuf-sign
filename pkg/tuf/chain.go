package tuf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Fetcher retrieves metadata files by role name ("root", "timestamp",
// "snapshot", "targets", "channel/develop", ...). Implementations are
// the mirror (HTTP) or the offline bundle; they return the raw file
// bytes. A role that does not exist must return an error.
type Fetcher interface {
	Fetch(role string) ([]byte, error)
}

// Updater carries trusted state: the current trusted root plus the
// last-known-good metadata per role (versions, expiries, hashes). It
// enforces rollback, freeze and mix-and-match across updates.
type Updater struct {
	root  *Root
	known map[string]FileMeta // role → last verified state
	now   func() time.Time
}

// NewUpdater starts from a trusted root: the bytes of a root.json the
// operator shipped with the binary or stored locally.
func NewUpdater(trustedRoot []byte, now func() time.Time) (*Updater, error) {
	env, err := decodeSigned(trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("tuf: trusted root: %w", err)
	}
	meta, err := Verify(env, RootRole, nil, 0, time.Time{})
	if err != nil {
		// Only structural decode; signatures of the trusted root are
		// checked on the first Update against itself.
		return nil, err
	}
	root, ok := meta.(*Root)
	if !ok {
		return nil, fmt.Errorf("tuf: trusted root: wrong type")
	}
	// The trusted root must verify against itself: a root that does
	// not carry its own declared threshold of signatures is not
	// trusted material, whatever the operator shipped.
	rootKeys, err := keysOf(root.Keys, root.Roles[RootRole].KeyIDs)
	if err != nil {
		return nil, fmt.Errorf("tuf: trusted root: %w", err)
	}
	if _, err := VerifySignature(env, rootKeys, root.Roles[RootRole].Threshold); err != nil {
		return nil, fmt.Errorf("tuf: trusted root: %w", err)
	}
	if now == nil {
		now = time.Now
	}
	u := &Updater{root: root, known: map[string]FileMeta{}, now: now}
	u.remember(RootRole, root, env.Signed)
	return u, nil
}

// Root returns the currently trusted root.
func (u *Updater) Root() *Root { return u.root }

// Known returns the last verified state of a role, if any.
func (u *Updater) Known(role string) (FileMeta, bool) {
	fm, ok := u.known[role]
	return fm, ok
}

// Update runs a full TUF refresh: root rotation (if any), timestamp,
// snapshot, targets and every channel role the snapshot pins.
func (u *Updater) Update(f Fetcher) (*Chain, error) {
	if err := u.updateRoot(f); err != nil {
		return nil, err
	}
	now := u.now()

	// 1. timestamp — signed by the root's timestamp role only.
	tsEnv, err := fetchSigned(f, TimestampRole)
	if err != nil {
		return nil, err
	}
	tsRole := u.root.Roles[TimestampRole]
	tsKeys, err := keysOf(u.root.Keys, tsRole.KeyIDs)
	if err != nil {
		return nil, err
	}
	tsAny, err := Verify(tsEnv, TimestampRole, tsKeys, tsRole.Threshold, now)
	if err != nil {
		return nil, err
	}
	ts := tsAny.(*Timestamp)
	if fm, ok := u.known[TimestampRole]; ok {
		if err := CheckRollback(ts, fm); err != nil {
			return nil, err
		}
		if err := CheckFreeze(ts, fm.expiry()); err != nil {
			return nil, err
		}
	}
	u.remember(TimestampRole, ts, tsEnv.Signed)

	// 2. snapshot — pinned by timestamp (mix-and-match), signed by
	// the root's snapshot role.
	snapFM, err := ts.SnapshotEntry()
	if err != nil {
		return nil, err
	}
	snapEnv, err := fetchSigned(f, SnapshotRole)
	if err != nil {
		return nil, err
	}
	if err := CheckMixAndMatch(snapEnv, snapFM); err != nil {
		return nil, err
	}
	snapRole := u.root.Roles[SnapshotRole]
	snapKeys, err := keysOf(u.root.Keys, snapRole.KeyIDs)
	if err != nil {
		return nil, err
	}
	snapAny, err := Verify(snapEnv, SnapshotRole, snapKeys, snapRole.Threshold, now)
	if err != nil {
		return nil, err
	}
	snap := snapAny.(*Snapshot)
	if fm, ok := u.known[SnapshotRole]; ok {
		if err := CheckRollback(snap, fm); err != nil {
			return nil, err
		}
		if err := CheckFreeze(snap, fm.expiry()); err != nil {
			return nil, err
		}
	}
	u.remember(SnapshotRole, snap, snapEnv.Signed)

	// 3. top-level targets — pinned by snapshot, signed by root's
	// targets role.
	targets, targetsEnv, err := u.fetchTargets(f, snap, TargetsRole, now)
	if err != nil {
		return nil, err
	}
	u.remember(TargetsRole, targets, targetsEnv.Signed)

	chain := &Chain{
		Root:      u.root,
		Timestamp: ts,
		Snapshot:  snap,
		Targets:   targets,
		Channels:  map[string]*Targets{},
	}

	// 4. delegated channel roles pinned by the snapshot.
	for _, dr := range delegatedChannels(targets) {
		fm, ok := snap.Meta[dr.Name]
		if !ok {
			return nil, fmt.Errorf("tuf: snapshot does not pin delegated role %q", dr.Name)
		}
		env, err := fetchSigned(f, dr.Name)
		if err != nil {
			return nil, err
		}
		if err := CheckMixAndMatch(env, fm); err != nil {
			return nil, err
		}
		dKeys, err := keysOf(targets.Delegations.Keys, dr.KeyIDs)
		if err != nil {
			return nil, err
		}
		any, err := Verify(env, TargetsRole, dKeys, dr.Threshold, now)
		if err != nil {
			return nil, fmt.Errorf("tuf: %s: %w", dr.Name, err)
		}
		ch := any.(*Targets)
		if km, ok := u.known[dr.Name]; ok {
			if err := CheckRollback(ch, km); err != nil {
				return nil, err
			}
			if err := CheckFreeze(ch, km.expiry()); err != nil {
				return nil, err
			}
		}
		u.remember(dr.Name, ch, env.Signed)
		chain.Channels[dr.Name] = ch
	}
	return chain, nil
}

// updateRoot walks the root chain: while the published root version is
// newer than the trusted one, each intermediate version must be signed
// both by the trusted root's root role and by its own new root role
// (thresholds of both), version strictly increasing, not expired.
func (u *Updater) updateRoot(f Fetcher) error {
	for {
		env, err := fetchSigned(f, RootRole)
		if err != nil {
			return err
		}
		newAny, err := Verify(env, RootRole, nil, 0, u.now())
		if err != nil {
			return err
		}
		nr := newAny.(*Root)
		if nr.Version == u.root.Version {
			// Same root; confirm it is self-signed.
			keys, err := keysOf(nr.Keys, nr.Roles[RootRole].KeyIDs)
			if err != nil {
				return err
			}
			if _, err := VerifySignature(env, keys, nr.Roles[RootRole].Threshold); err != nil {
				return fmt.Errorf("tuf: root: %w", err)
			}
			if bytes, err := env.SignedBytes(); err == nil {
				u.remember(RootRole, nr, bytes)
			}
			return nil
		}
		if nr.Version < u.root.Version {
			return fmt.Errorf("tuf: root rollback: published version %d < trusted %d", nr.Version, u.root.Version)
		}
		if nr.Version > u.root.Version+1 {
			return fmt.Errorf("tuf: root rotation must be stepwise: trusted %d, published %d", u.root.Version, nr.Version)
		}
		oldKeys, err := keysOf(u.root.Keys, u.root.Roles[RootRole].KeyIDs)
		if err != nil {
			return err
		}
		if _, err := VerifySignature(env, oldKeys, u.root.Roles[RootRole].Threshold); err != nil {
			return fmt.Errorf("tuf: new root not signed by previous root: %w", err)
		}
		newKeys, err := keysOf(nr.Keys, nr.Roles[RootRole].KeyIDs)
		if err != nil {
			return err
		}
		if _, err := VerifySignature(env, newKeys, nr.Roles[RootRole].Threshold); err != nil {
			return fmt.Errorf("tuf: new root not self-signed: %w", err)
		}
		if fm, ok := u.known[RootRole]; ok {
			if err := CheckFreeze(nr, fm.expiry()); err != nil {
				return err
			}
		}
		u.root = nr
		u.remember(RootRole, nr, env.Signed)
		// Loop: fetch the (now current) root again per spec; a
		// publisher serving exactly the trusted version exits above.
	}
}

// fetchTargets fetches and verifies a targets-family role pinned by
// the snapshot: top-level targets verify against the root's targets
// role; delegated roles against their delegations keys.
func (u *Updater) fetchTargets(f Fetcher, snap *Snapshot, role string, now time.Time) (*Targets, *Signed, error) {
	fm, ok := snap.Meta[role]
	if !ok {
		if role == TargetsRole {
			return nil, nil, fmt.Errorf("tuf: snapshot does not pin %q", TargetsRole)
		}
		return nil, nil, fmt.Errorf("tuf: snapshot does not pin %q", role)
	}
	env, err := fetchSigned(f, role)
	if err != nil {
		return nil, nil, err
	}
	if err := CheckMixAndMatch(env, fm); err != nil {
		return nil, nil, err
	}
	tr := u.root.Roles[TargetsRole]
	keys, err := keysOf(u.root.Keys, tr.KeyIDs)
	if err != nil {
		return nil, nil, err
	}
	any, err := Verify(env, TargetsRole, keys, tr.Threshold, now)
	if err != nil {
		return nil, nil, err
	}
	t := any.(*Targets)
	if km, ok := u.known[role]; ok {
		if err := CheckRollback(t, km); err != nil {
			return nil, nil, err
		}
		if err := CheckFreeze(t, km.expiry()); err != nil {
			return nil, nil, err
		}
	}
	return t, env, nil
}

func (u *Updater) remember(role string, meta Meta, signed []byte) {
	fm := FileMeta{Version: meta.MetaVersion(), Hashes: Hashes{hashAlgoSHA256: sha256Hex(signed)}}
	if !meta.MetaExpires().IsZero() {
		exp := meta.MetaExpires()
		fm.Expires = &exp
	}
	u.known[role] = fm
}

// Chain is a fully verified set of metadata from one update.
type Chain struct {
	Root      *Root
	Timestamp *Timestamp
	Snapshot  *Snapshot
	Targets   *Targets
	Channels  map[string]*Targets // delegated roles: "channel/develop", ...
}

// RoleTargets returns the targets map of a channel ("develop" →
// channel/develop) or of the top-level targets for an empty channel.
func (c *Chain) RoleTargets(channel string) (*Targets, bool) {
	if channel == "" {
		return c.Targets, true
	}
	t, ok := c.Channels[ChannelRolePrefix+channel]
	return t, ok
}

// Target finds a target in a channel.
func (c *Chain) Target(channel, path string) (*Target, bool) {
	t, ok := c.RoleTargets(channel)
	if !ok {
		return nil, false
	}
	tg, ok := t.Targets[path]
	if !ok {
		return nil, false
	}
	return &tg, true
}

// VerifyTarget checks artifact bytes against the target pinned in the
// given channel.
func (c *Chain) VerifyTarget(channel, path string, data []byte) error {
	tg, ok := c.Target(channel, path)
	if !ok {
		return fmt.Errorf("tuf: target %q not found in channel %q", path, channel)
	}
	if int64(len(data)) != tg.Length {
		return fmt.Errorf("tuf: target %q: length %d != pinned %d", path, len(data), tg.Length)
	}
	return tg.Hashes.Check(data)
}

// helpers

func decodeSigned(data []byte) (*Signed, error) {
	env := &Signed{}
	if err := json.Unmarshal(data, env); err != nil {
		return nil, fmt.Errorf("tuf: decode envelope: %w", err)
	}
	if len(env.Signed) == 0 {
		return nil, fmt.Errorf("tuf: envelope has empty signed object")
	}
	canon, err := Canonicalize(env.Signed)
	if err != nil {
		return nil, err
	}
	env.Signed = canon
	return env, nil
}

func fetchSigned(f Fetcher, role string) (*Signed, error) {
	raw, err := f.Fetch(role)
	if err != nil {
		return nil, fmt.Errorf("tuf: fetch %s: %w", role, err)
	}
	env, err := decodeSigned(raw)
	if err != nil {
		return nil, fmt.Errorf("tuf: fetch %s: %w", role, err)
	}
	return env, nil
}

func keysOf(pool map[string]Key, ids []string) (map[string]Key, error) {
	out := make(map[string]Key, len(ids))
	for _, id := range ids {
		k, ok := pool[id]
		if !ok {
			return nil, fmt.Errorf("tuf: role references unknown key %q", id)
		}
		if k.KeyID != "" && k.KeyID != id {
			return nil, fmt.Errorf("tuf: key %q declares mismatched id %q", id, k.KeyID)
		}
		out[id] = k
	}
	return out, nil
}

func delegatedChannels(t *Targets) []DelegatedRole {
	if t.Delegations == nil {
		return nil
	}
	var out []DelegatedRole
	for _, r := range t.Delegations.Roles {
		if len(r.Name) > len(ChannelRolePrefix) && r.Name[:len(ChannelRolePrefix)] == ChannelRolePrefix {
			out = append(out, r)
		}
	}
	return out
}

func (fm FileMeta) expiry() time.Time {
	if fm.Expires == nil {
		return time.Time{}
	}
	return *fm.Expires
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

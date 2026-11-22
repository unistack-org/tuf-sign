package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tuf "github.com/unistack-org/tuf-sign/pkg/tuf"
)

// dirMeta lists the role files the state dir maintains. Channels are
// discovered from channel-*.json files on disk.
var baseRoles = []string{tuf.RootRole, tuf.TargetsRole, tuf.SnapshotRole, tuf.TimestampRole}

// loadSigned reads and decodes one role file from the state dir.
func (s state) loadSigned(role string) (*tuf.Signed, error) {
	raw, err := os.ReadFile(s.metaPath(role))
	if err != nil {
		return nil, fmt.Errorf("read role %s: %w", role, err)
	}
	env := &tuf.Signed{}
	if err := json.Unmarshal(raw, env); err != nil {
		return nil, fmt.Errorf("decode role %s: %w", role, err)
	}
	return env, nil
}

// loadMeta reads one role file and decodes its signed object.
func (s state) loadMeta(role string) (tuf.Meta, error) {
	env, err := s.loadSigned(role)
	if err != nil {
		return nil, err
	}
	return tuf.Decode(env, role)
}

// channels lists channel names present in the state dir.
func (s state) channels() []string {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, "channel-") && strings.HasSuffix(n, ".json") {
			ch := strings.TrimSuffix(strings.TrimPrefix(n, "channel-"), ".json")
			if tuf.IsChannel(ch) {
				out = append(out, ch)
			}
		}
	}
	return out
}

// metaRoles is every role file snapshot must pin.
func (s state) metaRoles() []string {
	roles := []string{tuf.TargetsRole}
	for _, ch := range s.channels() {
		roles = append(roles, tuf.ChannelRolePrefix+ch)
	}
	return roles
}

// writeSigned atomically writes a signed role file into the state dir.
func (s state) writeSigned(role string, env *tuf.Signed) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return atomicWrite(s.metaPath(role), raw)
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// writeTargets atomically writes a release artefact under targets/.
func (s state) writeTargets(path string, data []byte) error {
	if err := checkTargetRelPath(path); err != nil {
		return err
	}
	return atomicWrite(s.targetPath(path), data)
}

// checkTargetRelPath rejects absolute paths and ".." in target paths.
func checkTargetRelPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return fmt.Errorf("invalid target path %q", p)
	}
	clean := filepath.ToSlash(filepath.Clean("/" + p))[1:]
	if clean != p || clean == "." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("invalid target path %q", p)
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// pinMeta builds the snapshot FileMeta entry for a signed role file
// (version/expiry/hash over the canonical signed bytes, the same bytes
// the mirror serves).
func pinMeta(env *tuf.Signed) (tuf.FileMeta, error) {
	canon, err := env.SignedBytes()
	if err != nil {
		return tuf.FileMeta{}, err
	}
	var hdr struct {
		Version int64     `json:"version"`
		Expires time.Time `json:"expires"`
	}
	if err := json.Unmarshal(canon, &hdr); err != nil {
		return tuf.FileMeta{}, err
	}
	exp := hdr.Expires
	return tuf.FileMeta{
		Version: hdr.Version,
		Expires: &exp,
		Hashes:  tuf.Hashes{"sha256": sha256Hex(canon)},
		Length:  int64(len(canon)),
	}, nil
}

// refresh re-pins snapshot and timestamp. Keys are ed25519 private keys.
func (s state) refresh(snapPriv, tsPriv ed25519.PrivateKey, now time.Time, snapExpires, tsExpires time.Duration) error {
	pin := func(role string) (tuf.FileMeta, error) {
		env, err := s.loadSigned(role)
		if err != nil {
			return tuf.FileMeta{}, err
		}
		return pinMeta(env)
	}
	// Current snapshot version (monotonic +1).
	snapVer := int64(0)
	if env, err := s.loadSigned(tuf.SnapshotRole); err == nil {
		if m, err := tuf.Decode(env, tuf.SnapshotRole); err == nil {
			snapVer = m.MetaVersion()
		}
	}
	snap := &tuf.Snapshot{
		Type:        tuf.SnapshotRole,
		Version:     snapVer + 1,
		SpecVersion: specVersion,
		Expires:     now.Add(snapExpires),
		Meta:        map[string]tuf.FileMeta{},
	}
	for _, role := range s.metaRoles() {
		fm, err := pin(role)
		if err != nil {
			return fmt.Errorf("pin %s: %w", role, err)
		}
		snap.Meta[role] = fm
	}
	snapEnv, err := tuf.SignCanonical(snap, snapPriv)
	if err != nil {
		return fmt.Errorf("sign snapshot: %w", err)
	}
	if err := s.writeSigned(tuf.SnapshotRole, snapEnv); err != nil {
		return err
	}

	tsVer := int64(0)
	if env, err := s.loadSigned(tuf.TimestampRole); err == nil {
		if m, err := tuf.Decode(env, tuf.TimestampRole); err == nil {
			tsVer = m.MetaVersion()
		}
	}
	fm, err := pinMeta(snapEnv)
	if err != nil {
		return err
	}
	ts := &tuf.Timestamp{
		Type:        tuf.TimestampRole,
		Version:     tsVer + 1,
		SpecVersion: specVersion,
		Expires:     now.Add(tsExpires),
		Meta:        map[string]tuf.FileMeta{tuf.SnapshotRole: fm},
	}
	tsEnv, err := tuf.SignCanonical(ts, tsPriv)
	if err != nil {
		return fmt.Errorf("sign timestamp: %w", err)
	}
	return s.writeSigned(tuf.TimestampRole, tsEnv)
}

// Package tuf is a minimal implementation of the TUF specification
// (subset of 1.0) built on the standard library only: ed25519 keys,
// canonical JSON, threshold signatures, rollback/freeze/mix-and-match
// protection and root rotation. Metadata is wire-compatible with the
// TUF specification (KMD-0006 key format, RFC3385-style signed
// envelopes), so test vectors can be cross-checked against the
// reference format.
//
// Deliberately NOT implemented (see todos/deploy/01-pkg-tuf.md):
// online signing services (Rekor/Fulcio), nested delegation trees
// beyond one level (channel roles), and license signing (that is a
// separate root-signed key, track 09).
package tuf

import (
	"encoding/json"
	"fmt"
	"time"
)

// Role names in the trust chain.
const (
	RootRole      = "root"
	SnapshotRole  = "snapshot"
	TimestampRole = "timestamp"
	TargetsRole   = "targets"
)

// ChannelRolePrefix prefixes delegated channel roles: "channel/develop".
const ChannelRolePrefix = "channel/"

// RoleFile is the canonical wire file name for a role
// ("root.json", "channel-develop.json"): the role name with '/'
// flattened to '-' plus the .json suffix. Producer and verifier must
// agree on this mapping.
func RoleFile(role string) string {
	return channelToName(role) + ".json"
}

// channelToName flattens a role name into a file name:
// "channel/develop" → "channel-develop".
func channelToName(role string) string {
	out := make([]rune, 0, len(role))
	for _, r := range role {
		switch r {
		case '/', '\\':
			out = append(out, '-')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

// Key is a TUF key (KMD-0006). Only ed25519 keys are supported.
// KeyID is the hex sha256 of the canonical JSON of the key object;
// it is optional on the wire (computed when empty).
type Key struct {
	KeyID   string `json:"id,omitempty"`
	KeyType string `json:"keytype"`
	Scheme  string `json:"scheme"`
	KeyVal  KeyVal `json:"keyval"`
}

// KeyVal holds the base64-encoded public key.
type KeyVal struct {
	Public string `json:"public"`
}

// KeyIDHex returns the canonical key id of k (sha256 of canonical JSON).
func (k Key) KeyIDHex() (string, error) {
	// The id hashes the key object without its own id field, so the
	// digest is a pure function of the public key material.
	k.KeyID = ""
	c, err := MarshalCanonical(k)
	if err != nil {
		return "", err
	}
	return KeyID(c), nil
}

// Signature is one role signature over the canonical JSON of a signed
// object: keyid of the signer plus base64 of the raw ed25519 signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Signed is the wire envelope: the signed object (raw canonical
// bytes are preserved on decode) plus its signatures.
type Signed struct {
	Signed     json.RawMessage `json:"signed"`
	Signatures []Signature     `json:"signatures"`
}

// Role is a threshold set of key ids.
type Role struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

// Delegations is the delegation section of a targets role.
type Delegations struct {
	Keys  map[string]Key  `json:"keys"`
	Roles []DelegatedRole `json:"roles"`
}

// DelegatedRole is one delegated role: name, path patterns, keys and
// threshold. Terminating stops the depth-first walk of delegations.
type DelegatedRole struct {
	Name        string   `json:"name"`
	Paths       []string `json:"paths"`
	KeyIDs      []string `json:"keyids"`
	Threshold   int      `json:"threshold"`
	Terminating bool     `json:"terminating,omitempty"`
}

// FileMeta is a per-file entry of the snapshot (and root) role:
// version, expiry and (optionally) the pinned hash of the file.
type FileMeta struct {
	Version int64      `json:"version"`
	Expires *time.Time `json:"expires,omitempty"`
	Hashes  Hashes     `json:"hashes,omitempty"`
	Length  int64      `json:"length,omitempty"`
}

// Hashes maps hash algorithm ("sha256", "sha512") to lowercase hex digest.
type Hashes map[string]string

// Target describes one artifact in a targets role.
type Target struct {
	Length int64           `json:"length"`
	Hashes Hashes          `json:"hashes"`
	Custom json.RawMessage `json:"custom,omitempty"`
}

// Root is the root role metadata.
type Root struct {
	Type        string          `json:"type"`
	Version     int64           `json:"version"`
	SpecVersion string          `json:"spec_version"`
	Expires     time.Time       `json:"expires"`
	Keys        map[string]Key  `json:"keys"`
	Roles       map[string]Role `json:"roles"`
	Consistent  bool            `json:"consistent_snapshot,omitempty"`
}

// Targets is a targets role metadata (top-level or delegated, e.g. a
// release channel).
type Targets struct {
	Type        string            `json:"type"`
	Version     int64             `json:"version"`
	SpecVersion string            `json:"spec_version"`
	Expires     time.Time         `json:"expires"`
	Targets     map[string]Target `json:"targets"`
	Keys        map[string]Key    `json:"keys,omitempty"`
	Delegations *Delegations      `json:"delegations,omitempty"`
}

// Snapshot is the snapshot role metadata: version/expiry/hash of every
// metadata file that the snapshot protects.
type Snapshot struct {
	Type        string              `json:"type"`
	Version     int64               `json:"version"`
	SpecVersion string              `json:"spec_version"`
	Expires     time.Time           `json:"expires"`
	Meta        map[string]FileMeta `json:"meta"`
}

// Timestamp is the timestamp role metadata: the pinned snapshot file.
type Timestamp struct {
	Type        string              `json:"type"`
	Version     int64               `json:"version"`
	SpecVersion string              `json:"spec_version"`
	Expires     time.Time           `json:"expires"`
	Meta        map[string]FileMeta `json:"meta"`
}

// SnapshotEntry returns the pinned snapshot file entry of the timestamp.
func (t *Timestamp) SnapshotEntry() (FileMeta, error) {
	fm, ok := t.Meta[SnapshotRole]
	if !ok {
		return FileMeta{}, fmt.Errorf("tuf: timestamp has no %q entry", SnapshotRole)
	}
	return fm, nil
}

// Meta is implemented by every role's signed object.
type Meta interface {
	Role() string
	MetaVersion() int64
	MetaExpires() time.Time
}

func (m *Root) Role() string           { return RootRole }
func (m *Root) MetaVersion() int64     { return m.Version }
func (m *Root) MetaExpires() time.Time { return m.Expires }

func (m *Targets) Role() string           { return TargetsRole }
func (m *Targets) MetaVersion() int64     { return m.Version }
func (m *Targets) MetaExpires() time.Time { return m.Expires }

func (m *Snapshot) Role() string           { return SnapshotRole }
func (m *Snapshot) MetaVersion() int64     { return m.Version }
func (m *Snapshot) MetaExpires() time.Time { return m.Expires }

func (m *Timestamp) Role() string           { return TimestampRole }
func (m *Timestamp) MetaVersion() int64     { return m.Version }
func (m *Timestamp) MetaExpires() time.Time { return m.Expires }

package main

import (
	"crypto/ed25519"
	"fmt"
	"time"

	tuf "github.com/unistack-org/tuf-sign/pkg/tuf"
)

// Role expiry defaults (spec 2026-11-03-updates-design.md).
const (
	defaultRootExpiry      = 365 * 24 * time.Hour
	defaultTargetsExpiry   = 180 * 24 * time.Hour
	defaultChannelExpiry   = 90 * 24 * time.Hour
	defaultSnapshotExpiry  = 7 * 24 * time.Hour
	defaultTimestampExpiry = 24 * time.Hour
)

// keyEntry builds the TUF key record + id for a public key.
func keyEntry(priv ed25519.PrivateKey) (string, tuf.Key) {
	k := tuf.KeyFromPublic(priv.Public().(ed25519.PublicKey))
	id, err := k.KeyIDHex()
	if err != nil {
		panic(err) // canonicalisation of a fixed struct cannot fail
	}
	k.KeyID = id
	return id, k
}

// runInitRoot creates root.json (signed by the offline root keys) and a
// top-level targets.json that delegates the channel roles, plus empty
// channel role files. This is the rare offline ceremony: run it once per
// root rotation, commit/deploy the produced files.
func runInitRoot(args []string) error {
	f, err := parseFlags(args, map[string]string{
		"state": "", "timestamp": "", "snapshot": "", "targets": "",
		"root-expires": "", "timestamp-expires": "", "snapshot-expires": "",
	}, []string{"root", "channel"})
	if err != nil {
		return err
	}
	st := state{dir: f.get("state")}
	if st.dir == "" {
		return fmt.Errorf("flag -state is required")
	}
	rootSpecs := f.getAll("root")
	if len(rootSpecs) == 0 {
		return fmt.Errorf("at least one -root KEYFILE is required")
	}
	tsPriv, err := loadKey(f.get("timestamp"))
	if err != nil {
		return err
	}
	snapPriv, err := loadKey(f.get("snapshot"))
	if err != nil {
		return err
	}
	tgPriv, err := loadKey(f.get("targets"))
	if err != nil {
		return err
	}
	rootPrivs := make([]ed25519.PrivateKey, 0, len(rootSpecs))
	for _, spec := range rootSpecs {
		p, err := loadKey(spec)
		if err != nil {
			return err
		}
		rootPrivs = append(rootPrivs, p)
	}
	chanPrivs := map[string]ed25519.PrivateKey{}
	for _, spec := range f.getAll("channel") {
		name, keyPath, ok := splitKV(spec)
		if !ok || !tuf.IsChannel(name) {
			return fmt.Errorf("-channel expects NAME=KEYFILE with NAME in develop|testing|stable, got %q", spec)
		}
		p, err := loadKey(keyPath)
		if err != nil {
			return err
		}
		chanPrivs[name] = p
	}
	rootExp, err := parseDur(f.get("root-expires"), defaultRootExpiry)
	if err != nil {
		return err
	}
	tsExp, err := parseDur(f.get("timestamp-expires"), defaultTimestampExpiry)
	if err != nil {
		return err
	}
	snapExp, err := parseDur(f.get("snapshot-expires"), defaultSnapshotExpiry)
	if err != nil {
		return err
	}
	now := nowUTC()

	rootID, rootKey := keyEntry(rootPrivs[0])
	tsID, tsKey := keyEntry(tsPriv)
	snapID, snapKey := keyEntry(snapPriv)
	tgID, tgKey := keyEntry(tgPriv)

	rootKeys := map[string]tuf.Key{rootID: rootKey, tsID: tsKey, snapID: snapKey, tgID: tgKey}
	rootIDs := make([]string, 0, len(rootPrivs))
	for _, p := range rootPrivs {
		id, k := keyEntry(p)
		rootKeys[id] = k
		rootIDs = append(rootIDs, id)
	}

	root := &tuf.Root{
		Type:        tuf.RootRole,
		Version:     1,
		SpecVersion: specVersion,
		Expires:     now.Add(rootExp),
		Keys:        rootKeys,
		Roles: map[string]tuf.Role{
			tuf.RootRole:      {KeyIDs: rootIDs, Threshold: len(rootPrivs)},
			tuf.TimestampRole: {KeyIDs: []string{tsID}, Threshold: 1},
			tuf.SnapshotRole:  {KeyIDs: []string{snapID}, Threshold: 1},
			tuf.TargetsRole:   {KeyIDs: []string{tgID}, Threshold: 1},
		},
	}
	rootEnv, err := tuf.SignCanonical(root, rootPrivs...)
	if err != nil {
		return err
	}
	if err := st.writeSigned(tuf.RootRole, rootEnv); err != nil {
		return err
	}

	// Top-level targets with one delegation per channel.
	tg := &tuf.Targets{
		Type:        tuf.TargetsRole,
		Version:     1,
		SpecVersion: specVersion,
		Expires:     now.Add(defaultTargetsExpiry),
		Targets:     map[string]tuf.Target{},
		Keys:        map[string]tuf.Key{tgID: tgKey},
	}
	if len(chanPrivs) > 0 {
		tg.Delegations = &tuf.Delegations{Keys: map[string]tuf.Key{}}
		for _, ch := range tuf.ChannelOrder {
			cp, ok := chanPrivs[ch]
			if !ok {
				continue
			}
			ck, ckKey := keyEntry(cp)
			tg.Delegations.Keys[ck] = ckKey
			tg.Delegations.Roles = append(tg.Delegations.Roles, tuf.DelegatedRole{
				Name:      tuf.ChannelRolePrefix + ch,
				Paths:     []string{"*"},
				KeyIDs:    []string{ck},
				Threshold: 1,
			})
			// Empty channel role so publish/promote have a base.
			ct := &tuf.Targets{
				Type:        tuf.TargetsRole,
				Version:     1,
				SpecVersion: specVersion,
				Expires:     now.Add(defaultChannelExpiry),
				Targets:     map[string]tuf.Target{},
				Keys:        map[string]tuf.Key{ck: ckKey},
			}
			ctEnv, err := tuf.SignCanonical(ct, cp)
			if err != nil {
				return err
			}
			if err := st.writeSigned(tuf.ChannelRolePrefix+ch, ctEnv); err != nil {
				return err
			}
		}
	}
	tgEnv, err := tuf.SignCanonical(tg, tgPriv)
	if err != nil {
		return err
	}
	if err := st.writeSigned(tuf.TargetsRole, tgEnv); err != nil {
		return err
	}

	// Seed snapshot+timestamp so the tree is fetchable from day one.
	if err := st.refresh(snapPriv, tsPriv, now, snapExp, tsExp); err != nil {
		return err
	}
	fmt.Printf("root.json (threshold %d/%d), targets.json, %d channel role files, snapshot+timestamp written to %s\n",
		len(rootPrivs), len(rootPrivs), len(chanPrivs), st.dir)
	return nil
}

func splitKV(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

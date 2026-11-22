package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tuf "github.com/unistack-org/tuf-sign/pkg/tuf"
)

// knownImpactKeys are the impact keys the update CLI understands.
var knownImpactKeys = map[string]bool{
	"agent_restart":    true,
	"host_reboot":      true,
	"drain":            true,
	"vm_restart":       true,
	"cell_maintenance": true,
}

type publishParams struct {
	channel      string
	binaries     []string
	version      string
	critical     bool
	migrations   bool
	notesURL     string
	minFrom      string
	impact       map[string]tuf.Level
	mirrors      []string
	artifactsOut string
}

// runPublish adds release binaries (one -binary per arch, all must
// share -version) to a channel: the channel role gains the targets and
// snapshot+timestamp are re-pinned once. Artefacts are NOT written into
// <state>/targets/ — the tree on the CDN is metadata-only; the new
// binaries land in -artifacts-out for direct upload next to the
// metadata.
func runPublish(args []string) error {
	f, err := parseFlags(args, map[string]string{
		"state": "", "channel": "", "version": "",
		"critical": "", "migrations": "", "notes-url": "", "min-from": "",
		"impact": "", "mirrors": "", "artifacts-out": "",
		"key-snapshot": "", "key-timestamp": "", "key-channel": "",
		"channel-expires":  "",
		"snapshot-expires": "", "timestamp-expires": "",
	}, []string{"binary"})
	if err != nil {
		return err
	}
	st := state{dir: f.get("state")}
	if st.dir == "" {
		return fmt.Errorf("flag -state is required")
	}
	p := publishParams{
		channel:      f.get("channel"),
		binaries:     f.getAll("binary"),
		version:      f.get("version"),
		notesURL:     f.get("notes-url"),
		minFrom:      f.get("min-from"),
		artifactsOut: f.get("artifacts-out"),
	}
	if !tuf.IsChannel(p.channel) {
		return fmt.Errorf("-channel must be develop|testing|stable, got %q", p.channel)
	}
	if len(p.binaries) == 0 {
		return fmt.Errorf("flag -binary is required (repeat it per arch)")
	}
	if p.version == "" {
		return fmt.Errorf("flag -version is required")
	}
	if p.critical, err = parseBool(f.get("critical")); err != nil {
		return fmt.Errorf("-critical: %w", err)
	}
	if p.migrations, err = parseBool(f.get("migrations")); err != nil {
		return fmt.Errorf("-migrations: %w", err)
	}
	p.impact, err = parseImpact(f.get("impact"))
	if err != nil {
		return err
	}
	if m := f.get("mirrors"); m != "" {
		p.mirrors = strings.Split(m, ",")
	}
	snapPriv, tsPriv, chanPriv, err := loadOnlineKeys(f, p.channel)
	if err != nil {
		return err
	}
	if p.artifactsOut == "" {
		return fmt.Errorf("flag -artifacts-out is required (dir for the content-addressed artefacts to upload)")
	}
	if err := os.MkdirAll(p.artifactsOut, 0o755); err != nil {
		return fmt.Errorf("create -artifacts-out: %w", err)
	}
	return publish(st, p, chanPriv, snapPriv, tsPriv,
		duration(f.get("channel-expires"), defaultChannelExpiry),
		duration(f.get("snapshot-expires"), defaultSnapshotExpiry),
		duration(f.get("timestamp-expires"), defaultTimestampExpiry))
}

// publish pins every binary into the channel role, then re-pins
// snapshot+timestamp exactly once. The channel version bump is applied
// only when at least one target changed, so a fully idempotent re-run
// leaves the metadata byte-identical.
func publish(st state, p publishParams, chanPriv, snapPriv, tsPriv ed25519.PrivateKey,
	chanExp, snapExp, tsExp time.Duration) error {
	now := nowUTC()
	role := tuf.ChannelRolePrefix + p.channel

	meta, err := loadChannel(st, p.channel)
	if err != nil {
		return err
	}
	changed := false
	for _, bin := range p.binaries {
		data, err := os.ReadFile(bin)
		if err != nil {
			return fmt.Errorf("read binary: %w", err)
		}
		if len(data) == 0 {
			return fmt.Errorf("binary %s is empty", bin)
		}
		arch, err := archFromBinary(bin)
		if err != nil {
			return err
		}
		sum := sha256Hex(data)
		path := sum + ".cell-linux-" + arch

		custom := tuf.Custom{
			Version:    p.version,
			Critical:   p.critical,
			MinFrom:    p.minFrom,
			Migrations: p.migrations,
			NotesURL:   p.notesURL,
			Impact:     p.impact,
		}
		for _, m := range p.mirrors {
			custom.Mirrors = append(custom.Mirrors, tuf.Mirror{URL: m, Weight: 1})
		}
		craw, err := custom.Marshal()
		if err != nil {
			return err
		}
		tg := tuf.Target{Length: int64(len(data)), Hashes: tuf.Hashes{"sha256": sum}, Custom: craw}

		// Content-addressed path: republishing the same bytes with the
		// same metadata must not bump the role version (idempotent
		// re-runs, CI retries).
		if old, ok := meta.Targets[path]; ok {
			if old.Hashes["sha256"] != sum {
				return fmt.Errorf("target %s already pinned to a different hash", path)
			}
			oc, err1 := tuf.ParseCustom(old.Custom)
			nc, err2 := tuf.ParseCustom(craw)
			if err1 != nil || err2 != nil {
				return fmt.Errorf("target %s: custom: %v%v", path, err1, err2)
			}
			ocJ, _ := oc.Marshal()
			ncJ, _ := nc.Marshal()
			if string(ocJ) == string(ncJ) {
				fmt.Printf("target %s (version %s) already in channel %s — nothing to do\n", path, p.version, p.channel)
				continue
			}
			old.Custom = craw
			meta.Targets[path] = old
		} else {
			meta.Targets[path] = tg
		}
		changed = true

		// Artefact for direct upload: a pinned target must be fetchable
		// the moment the metadata is published, so deploy-tuf.sh uploads
		// artifacts BEFORE re-signing is not required — the file is
		// staged here and uploaded before the metadata ships.
		if err := checkTargetRelPath(path); err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(p.artifactsOut, path), data); err != nil {
			return fmt.Errorf("stage artefact: %w", err)
		}
		fmt.Printf("staged %s (%d bytes, sha256 %s)\n", path, len(data), sum)
	}
	if !changed {
		return nil
	}
	meta.Version++
	meta.Expires = now.Add(chanExp)
	newEnv, err := tuf.SignCanonical(meta, chanPriv)
	if err != nil {
		return err
	}
	if err := st.writeSigned(role, newEnv); err != nil {
		return err
	}
	if err := st.refresh(snapPriv, tsPriv, now, snapExp, tsExp); err != nil {
		return err
	}
	for _, bin := range p.binaries {
		fmt.Printf("published %s to channel %s from %s\n", p.version, p.channel, bin)
	}
	return nil
}

// loadChannel reads a channel role, creating an empty one when the
// tree has no such channel yet (channels are declared at init-root,
// but a publish is allowed to bootstrap one).
func loadChannel(st state, channel string) (*tuf.Targets, error) {
	role := tuf.ChannelRolePrefix + channel
	env, err := st.loadSigned(role)
	if err == nil {
		// Channel roles are targets-typed; Decode matches on "type".
		m, err := tuf.Decode(env, tuf.TargetsRole)
		if err != nil {
			return nil, err
		}
		tg, ok := m.(*tuf.Targets)
		if !ok {
			return nil, fmt.Errorf("role %s is not a targets role", role)
		}
		return tg, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	return &tuf.Targets{
		Type:        tuf.TargetsRole,
		Version:     0,
		SpecVersion: specVersion,
		Expires:     nowUTC().Add(defaultChannelExpiry),
		Targets:     map[string]tuf.Target{},
	}, nil
}

// loadOnlineKeys loads the snapshot/timestamp/channel private keys.
func loadOnlineKeys(f *flags, channel string) (snap, ts, chanKey ed25519.PrivateKey, err error) {
	if snap, err = loadKey(f.get("key-snapshot")); err != nil {
		return
	}
	if ts, err = loadKey(f.get("key-timestamp")); err != nil {
		return
	}
	kp := f.get("key-channel")
	if kp == "" {
		err = fmt.Errorf("flag -key-channel is required (%s signing key)", channel)
		return
	}
	chanKey, err = loadKey(kp)
	return
}

// archFromBinary derives the target arch from the binary file name
// (cell-linux-amd64 → amd64); an explicit -arch flag overrides upstream.
func archFromBinary(path string) (string, error) {
	base := path[strings.LastIndex(path, "/")+1:]
	if i := strings.Index(base, ".cell-linux-"); i >= 0 {
		base = base[:i]
	}
	if i := strings.LastIndex(base, "-"); i >= 0 {
		base = base[i+1:]
	}
	switch base {
	case "amd64", "arm64":
		return base, nil
	}
	return "", fmt.Errorf("cannot derive arch from %q (name it cell-linux-{amd64,arm64} or use -arch)", path)
}

func parseImpact(s string) (map[string]tuf.Level, error) {
	if s == "" {
		return nil, nil
	}
	out := map[string]tuf.Level{}
	for _, pair := range strings.Split(s, ",") {
		k, v, ok := splitKV(pair)
		if !ok {
			return nil, fmt.Errorf("-impact expects key=level, got %q", pair)
		}
		if !knownImpactKeys[k] {
			return nil, fmt.Errorf("-impact: unknown key %q (known: agent_restart, host_reboot, drain, vm_restart, cell_maintenance)", k)
		}
		lvl := tuf.Level(v)
		if !lvl.Valid() {
			return nil, fmt.Errorf("-impact: %q has invalid level %q (want recommended|required)", k, v)
		}
		out[k] = lvl
	}
	return out, nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "false", "0", "no":
		return false, nil
	case "true", "1", "yes":
		return true, nil
	}
	return false, fmt.Errorf("invalid boolean %q", s)
}

func duration(s string, def time.Duration) time.Duration {
	d, err := parseDur(s, def)
	if err != nil {
		return def
	}
	return d
}

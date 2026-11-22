package main

import (
	"fmt"
	"os"
	"strings"

	tuf "github.com/unistack-org/tuf-sign/pkg/tuf"
)

// runPromote copies already-published targets (identical hashes) from a
// junior channel into a senior one, re-signing everything with the
// senior channel key. -path is repeatable (e.g. both arches of one
// release); the channel/snapshot/timestamp bump happens once.
func runPromote(args []string) error {
	f, err := parseFlags(args, map[string]string{
		"state": "", "from": tuf.ChannelDevelop, "to": "",
		"key-snapshot": "", "key-timestamp": "", "key-channel": "",
		"channel-expires": "", "snapshot-expires": "", "timestamp-expires": "",
	}, []string{"path", "artifact"})
	if err != nil {
		return err
	}
	st := state{dir: f.get("state")}
	if st.dir == "" {
		return fmt.Errorf("flag -state is required")
	}
	from, to := f.get("from"), f.get("to")
	if !tuf.IsChannel(from) || !tuf.IsChannel(to) {
		return fmt.Errorf("-from/-to must be develop|testing|stable")
	}
	// -path accepts repeats and commas (CI convenience).
	var paths []string
	for _, p := range f.getAll("path") {
		for _, part := range strings.Split(p, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				paths = append(paths, part)
			}
		}
	}
	if len(paths) == 0 {
		return fmt.Errorf("flag -path is required (target path as published)")
	}
	artifacts := f.getAll("artifact")
	if len(artifacts) > 0 && len(artifacts) != len(paths) {
		return fmt.Errorf("-artifact must be given once per -path (%d paths, %d artefacts)", len(paths), len(artifacts))
	}
	snapPriv, tsPriv, chanPriv, err := loadOnlineKeys(f, to)
	if err != nil {
		return err
	}

	// Source targets must exist in the junior channel.
	src, err := loadChannel(st, from)
	if err != nil {
		return err
	}

	role := tuf.ChannelRolePrefix + to
	dst, err := loadChannel(st, to)
	if err != nil {
		return err
	}
	promoted := 0
	for i, path := range paths {
		tg, ok := src.Targets[path]
		if !ok {
			return fmt.Errorf("target %s not in channel %s", path, from)
		}
		// The artefact is promoted byte-for-byte, content-addressed: it
		// is already on the CDN (uploaded when it was published to the
		// source channel), so it is only re-verified here. With
		// -artifact the files are read from local paths (a metadata-only
		// state dir has no targets/ subtree); without it the legacy
		// layout is used.
		if err := verifyPromotionSource(st, path, tg, artifacts, i); err != nil {
			return err
		}
		if old, ok := dst.Targets[path]; ok && old.Hashes["sha256"] == tg.Hashes["sha256"] {
			fmt.Printf("target %s already in channel %s (version %d) — nothing to do\n", path, to, dst.Version)
			continue
		}
		dst = tuf.PromoteTarget(dst, to, path, tg)
		promoted++
		fmt.Printf("promoted %s from %s to %s\n", path, from, to)
	}
	if promoted == 0 {
		return nil
	}
	dst.Expires = nowUTC().Add(duration(f.get("channel-expires"), defaultChannelExpiry))
	env, err := tuf.SignCanonical(dst, chanPriv)
	if err != nil {
		return err
	}
	if err := st.writeSigned(role, env); err != nil {
		return err
	}
	if err := st.refresh(snapPriv, tsPriv, nowUTC(),
		duration(f.get("snapshot-expires"), defaultSnapshotExpiry),
		duration(f.get("timestamp-expires"), defaultTimestampExpiry)); err != nil {
		return err
	}
	fmt.Printf("promoted %d target(s) from %s to %s (channel role version %d)\n", promoted, from, to, dst.Version)
	return nil
}

// verifyPromotionSource confirms the artefact bytes match the pin from
// the source channel. With -artifact files (count == -path count) the
// artefact is taken positionally; otherwise from the legacy
// <state>/targets/<path> location.
func verifyPromotionSource(st state, path string, tg tuf.Target, artifacts []string, idx int) error {
	sum := tg.Hashes["sha256"]
	if sum == "" {
		return fmt.Errorf("target %s has no sha256 hash", path)
	}
	src := st.targetPath(path)
	if len(artifacts) > 0 {
		src = artifacts[idx]
	}
	data, err := os.ReadFile(src)
	if err != nil {
		if len(artifacts) > 0 {
			return fmt.Errorf("read artefact %s: %w", src, err)
		}
		return fmt.Errorf("artefact for %s must be in the state dir or passed via -artifact: %w", path, err)
	}
	if sha256Hex(data) != sum {
		return fmt.Errorf("artefact for %s does not match the pinned hash", path)
	}
	return nil
}

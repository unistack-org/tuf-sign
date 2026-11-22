package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	tuf "github.com/unistack-org/tuf-sign/pkg/tuf"
)

// dirMirror serves a state directory as a tuf.Fetcher (role → file)
// and its targets/ subtree as artefact storage — the same layout the
// CDN serves under /tuf/.
type dirMirror struct{ st state }

// Fetch implements tuf.Fetcher.
func (m dirMirror) Fetch(role string) ([]byte, error) {
	return os.ReadFile(m.st.metaPath(role))
}

// runVerify walks the full TUF chain from the trusted root.json in the
// state dir. Without -metadata-only/-check-binary it then re-hashes
// every artefact the pinned channel targets reference (full audit);
// -metadata-only skips artefacts entirely, and -check-binary (repeatable)
// checks only the given files against the pins. Exit non-zero on any
// failure.
func runVerify(args []string) error {
	f, err := parseFlags(args, map[string]string{
		"state": "", "channel": "", "metadata-only": "",
	}, []string{"check-binary"})
	if err != nil {
		return err
	}
	checkBinaries := f.getAll("check-binary")
	metaOnly, err := parseBool(f.get("metadata-only"))
	if err != nil {
		return fmt.Errorf("-metadata-only: %w", err)
	}
	if metaOnly && len(checkBinaries) > 0 {
		return fmt.Errorf("-metadata-only and -check-binary are mutually exclusive")
	}
	st := state{dir: f.get("state")}
	if st.dir == "" {
		return fmt.Errorf("flag -state is required")
	}
	rootRaw, err := os.ReadFile(st.metaPath(tuf.RootRole))
	if err != nil {
		return fmt.Errorf("read root: %w", err)
	}
	up, err := tuf.NewUpdater(rootRaw, nil)
	if err != nil {
		return fmt.Errorf("trusted root: %w", err)
	}
	chain, err := up.Update(dirMirror{st})
	if err != nil {
		return fmt.Errorf("chain update: %w", err)
	}
	fmt.Println("verify: chain root→timestamp→snapshot→targets→channels OK")

	channels := []string{}
	if c := f.get("channel"); c != "" {
		if !tuf.IsChannel(c) {
			return fmt.Errorf("-channel must be develop|testing|stable")
		}
		channels = append(channels, c)
	} else {
		for _, ch := range tuf.ChannelOrder {
			if _, ok := chain.RoleTargets(ch); ok {
				channels = append(channels, ch)
			}
		}
	}
	n := 0
	for _, ch := range channels {
		tg, ok := chain.RoleTargets(ch)
		if !ok {
			return fmt.Errorf("channel %s not published", ch)
		}
		if metaOnly {
			n += len(tg.Targets)
			fmt.Printf("verify: channel %s — %d targets (metadata only)\n", ch, len(tg.Targets))
			continue
		}
		if len(checkBinaries) > 0 {
			continue
		}
		for path, target := range tg.Targets {
			if err := verifyArtefact(st, chain, ch, path, target); err != nil {
				return err
			}
			n++
		}
		fmt.Printf("verify: channel %s — %d targets, hashes verified\n", ch, len(tg.Targets))
	}
	if len(checkBinaries) > 0 {
		n, err = verifyBinaries(st, chain, channels, checkBinaries)
		if err != nil {
			return err
		}
	}
	what := "artefacts verified"
	if metaOnly {
		what = "targets (metadata only)"
	}
	if len(checkBinaries) > 0 {
		what = "binaries verified against channel pins"
	}
	fmt.Printf("verify: %d %s\n", n, what)
	return nil
}

// verifyBinaries checks the given local files against the pins of the
// selected channels: each file must be pinned (content-addressed path
// from its hash and name) in at least one of them, and must satisfy
// chain.VerifyTarget. History on the CDN is not re-hashed.
func verifyBinaries(st state, chain *tuf.Chain, channels, files []string) (int, error) {
	n := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return n, fmt.Errorf("read %s: %w", file, err)
		}
		arch, err := archFromBinary(file)
		if err != nil {
			return n, err
		}
		path := sha256Hex(data) + ".cell-linux-" + arch
		found := false
		for _, ch := range channels {
			tg, ok := chain.RoleTargets(ch)
			if !ok {
				continue
			}
			target, ok := tg.Targets[path]
			if !ok {
				continue
			}
			found = true
			if err := verifyPinnedArtefact(chain, ch, path, target, data); err != nil {
				return n, err
			}
			fmt.Printf("verify: channel %s target %s OK\n", ch, path)
		}
		if !found {
			return n, fmt.Errorf("binary %s: %s is not pinned in channel(s) %s",
				file, path, strings.Join(channels, ", "))
		}
		n++
	}
	return n, nil
}

// verifyPinnedArtefact validates bytes against a pinned target
// (length, chain-signature-anchored hash, custom sanity).
func verifyPinnedArtefact(chain *tuf.Chain, channel, path string, target tuf.Target, data []byte) error {
	if int64(len(data)) != target.Length {
		return fmt.Errorf("channel %s target %s: length %d, metadata says %d", channel, path, len(data), target.Length)
	}
	if err := chain.VerifyTarget(channel, path, data); err != nil {
		return fmt.Errorf("channel %s target %s: %w", channel, path, err)
	}
	if _, err := tuf.ParseCustom(target.Custom); err != nil {
		return fmt.Errorf("channel %s target %s: custom: %w", channel, path, err)
	}
	var probe map[string]any
	if err := json.Unmarshal(target.Custom, &probe); err != nil {
		return fmt.Errorf("channel %s target %s: custom json: %w", channel, path, err)
	}
	if v, _ := probe["version"].(string); v == "" {
		return fmt.Errorf("channel %s target %s: custom.version is empty", channel, path)
	}
	return nil
}

func verifyArtefact(st state, chain *tuf.Chain, channel, path string, target tuf.Target) error {
	data, err := os.ReadFile(st.targetPath(path))
	if err != nil {
		return fmt.Errorf("channel %s target %s: artefact missing: %w", channel, path, err)
	}
	return verifyPinnedArtefact(chain, channel, path, target, data)
}

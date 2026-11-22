// Command tuf-sign is the CI signing tool for the unistack update
// framework (todos/deploy/02). It operates on a state directory laid
// out exactly like the CDN's /tuf/ metadata (role files at the root),
// so a CI run is: download the metadata from /tuf/ → mutate with this
// tool → verify → rsync the metadata back. Release binaries never
// round-trip through the state dir: publish stages them (content-
// addressed) in -artifacts-out for direct upload to /tuf/targets/.
//
// Subcommands:
//
//	genkey     generate an ed25519 key file (hex seed)
//	init-root  build root.json + top-level targets.json (offline, rare)
//	publish    add a release binary to a channel, re-pin snapshot+timestamp
//	promote    re-sign an existing target into a more senior channel
//	resign     re-sign timestamp (and snapshot near expiry) — cron job
//	verify     full TUF chain check of the state dir + artefact hashes
//
// Root keys never enter CI: root.json is signed offline by init-root and
// deployed as a static file. CI holds only the online keys (timestamp,
// snapshot, the channel being published) as secrets rendered to files.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const specVersion = "1.0.0"

func usage() {
	fmt.Fprint(os.Stderr, `usage: tuf-sign <command> [flags]

commands:
  genkey     -out KEYFILE
  init-root  -state DIR -root K [-root K]... -timestamp K -snapshot K -targets K [-channel NAME=K]... [-root-expires 365d]
  publish    -state DIR -channel NAME -binary FILE [-binary FILE]... -version V -artifacts-out DIR
             [-critical] [-migrations] [-notes-url URL] [-min-from V]
             [-impact k=level,k=level] -key-snapshot K -key-timestamp K -key-channel K
  promote    -state DIR -from develop -to stable -path TARGETPATH [-path … | comma list]
             [-artifact FILE]… (one per -path, positional)
             -key-snapshot K -key-timestamp K -key-channel K
  resign     -state DIR -key-snapshot K -key-timestamp K
  verify     -state DIR [-channel NAME] [-metadata-only | -check-binary FILE]...
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = runGenKey(os.Args[2:])
	case "init-root":
		err = runInitRoot(os.Args[2:])
	case "publish":
		err = runPublish(os.Args[2:])
	case "promote":
		err = runPromote(os.Args[2:])
	case "resign":
		err = runResign(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tuf-sign:", err)
		os.Exit(1)
	}
}

// ── keys ──────────────────────────────────────────────────────────────

// loadKey reads a hex ed25519 seed key file (64 hex chars).
func loadKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("key %s: not hex: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key %s: seed is %d bytes, want %d", path, len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func runGenKey(args []string) error {
	f, err := parseFlags(args, map[string]string{"out": ""}, nil)
	if err != nil {
		return err
	}
	out, err := f.need("out")
	if err != nil {
		return err
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("key written to %s (public %s)\n", out, hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	return nil
}

// ── state directory helpers ───────────────────────────────────────────

// state is a TUF metadata directory laid out like CDN /tuf/:
// root.json, targets.json, channel-<name>.json, snapshot.json,
// timestamp.json, targets/<path>.
type state struct{ dir string }

func (s state) metaPath(role string) string {
	return filepath.Join(s.dir, roleFileNameOf(role))
}

func (s state) targetPath(p string) string {
	return filepath.Join(s.dir, "targets", filepath.FromSlash(p))
}

// roleFileNameOf mirrors tuf.RoleFile (channel/x → channel-x.json).
func roleFileNameOf(role string) string {
	return strings.ReplaceAll(role, "/", "-") + ".json"
}

// ── small flag parsing (package-internal, no deps) ───────────────────

type flags struct {
	fs   map[string]*string
	more map[string]*[]string
}

// boolFlags take an optional value: bare "-critical" means true
// (CI passes them without a value; "-critical true" also works).
var boolFlags = map[string]bool{"metadata-only": true, "critical": true, "migrations": true}

func parseFlags(args []string, defs map[string]string, multi []string) (*flags, error) {
	f := &flags{fs: map[string]*string{}, more: map[string]*[]string{}}
	for k, v := range defs {
		vv := v
		f.fs[k] = &vv
	}
	for _, k := range multi {
		kk := k
		f.more[kk] = &[]string{}
	}
	set := map[string]bool{}
	for _, k := range multi {
		set[k] = true
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			return nil, fmt.Errorf("unexpected argument %q", a)
		}
		name := strings.TrimLeft(a, "-")
		if set[name] {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("flag -%s needs a value", name)
			}
			i++
			*f.more[name] = append(*f.more[name], args[i])
			continue
		}
		sp, ok := f.fs[name]
		if !ok {
			return nil, fmt.Errorf("unknown flag -%s", name)
		}
		if boolFlags[name] && (i+1 >= len(args) || strings.HasPrefix(args[i+1], "-")) {
			*sp = "true"
			continue
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("flag -%s needs a value", name)
		}
		i++
		*sp = args[i]
	}
	return f, nil
}

func (f *flags) get(name string) string      { return *f.fs[name] }
func (f *flags) getAll(name string) []string { return *f.more[name] }
func (f *flags) need(name string) (string, error) {
	v := *f.fs[name]
	if v == "" {
		return "", fmt.Errorf("flag -%s is required", name)
	}
	return v, nil
}

func parseDur(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	return time.ParseDuration(s)
}

func nowUTC() time.Time { return time.Now().UTC().Truncate(time.Second) }

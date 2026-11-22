package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tuf "github.com/unistack-org/tuf-sign/pkg/tuf"
)

type testKeys struct {
	dir     string
	root    string
	ts      string
	snap    string
	topTgt  string
	develop string
	testing string
	stable  string
	outs    map[string]string
}

func newTestKeys(t *testing.T) *testKeys {
	t.Helper()
	dir := t.TempDir()
	k := &testKeys{dir: dir}
	mk := func(name string, dst *string) {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name+".key")
		if err := os.WriteFile(p, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		*dst = p
	}
	mk("root", &k.root)
	mk("timestamp", &k.ts)
	mk("snapshot", &k.snap)
	mk("targets", &k.topTgt)
	mk("channel-develop", &k.develop)
	mk("channel-testing", &k.testing)
	mk("channel-stable", &k.stable)
	return k
}

func (k *testKeys) keyFor(t *testing.T, role string) string {
	switch role {
	case tuf.RootRole:
		return k.root
	case tuf.TimestampRole:
		return k.ts
	case tuf.SnapshotRole:
		return k.snap
	case tuf.TargetsRole:
		return k.topTgt
	case tuf.ChannelRolePrefix + "develop":
		return k.develop
	case tuf.ChannelRolePrefix + "testing":
		return k.testing
	case tuf.ChannelRolePrefix + "stable":
		return k.stable
	}
	t.Fatalf("no key for role %s", role)
	return ""
}

func newStateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "tuf")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func (k *testKeys) initRoot(t *testing.T, stDir string) {
	t.Helper()
	err := runInitRoot([]string{
		"-state", stDir,
		"-root", k.root,
		"-timestamp", k.ts,
		"-snapshot", k.snap,
		"-targets", k.topTgt,
		"-channel", "develop=" + k.develop,
		"-channel", "testing=" + k.testing,
		"-channel", "stable=" + k.stable,
	})
	if err != nil {
		t.Fatalf("init-root: %v", err)
	}
}

func (k *testKeys) channelKey(t *testing.T, channel string) string {
	switch channel {
	case "develop":
		return k.develop
	case "testing":
		return k.testing
	case "stable":
		return k.stable
	}
	t.Fatalf("unknown channel %q", channel)
	return ""
}

func (k *testKeys) publish(t *testing.T, stDir, channel, bin, version string) {
	t.Helper()
	if err := runPublish([]string{
		"-state", stDir, "-channel", channel, "-binary", bin, "-version", version,
		"-artifacts-out", k.outDir(t, stDir),
		"-key-snapshot", k.snap, "-key-timestamp", k.ts, "-key-channel", k.channelKey(t, channel),
		"-impact", "agent_restart=recommended",
	}); err != nil {
		t.Fatalf("publish %s %s: %v", channel, version, err)
	}
	k.stageToState(t, stDir)
}

// outDir is the -artifacts-out dir paired with a state dir.
func (k *testKeys) outDir(t *testing.T, stDir string) string {
	t.Helper()
	if d, ok := k.outs[stDir]; ok {
		return d
	}
	d := filepath.Join(t.TempDir(), "dist")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if k.outs == nil {
		k.outs = map[string]string{}
	}
	k.outs[stDir] = d
	return d
}

// publishMulti publishes several binaries in one invocation.
func (k *testKeys) publishMulti(t *testing.T, stDir, channel string, bins []string, version string) {
	t.Helper()
	args := []string{
		"-state", stDir, "-channel", channel, "-version", version,
		"-artifacts-out", k.outDir(t, stDir),
		"-key-snapshot", k.snap, "-key-timestamp", k.ts, "-key-channel", k.channelKey(t, channel),
		"-impact", "agent_restart=recommended",
	}
	for _, b := range bins {
		args = append(args, "-binary", b)
	}
	if err := runPublish(args); err != nil {
		t.Fatalf("publish %s %s: %v", channel, version, err)
	}
}

// stageToState copies staged artefacts into <state>/targets/ — the
// legacy layout a manual full audit expects.
func (k *testKeys) stageToState(t *testing.T, stDir string) {
	t.Helper()
	src := k.outDir(t, stDir)
	raw, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range raw {
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(stDir, "targets"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stDir, "targets", e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func (k *testKeys) promote(t *testing.T, stDir, from, to, path string) {
	t.Helper()
	err := runPromote([]string{
		"-state", stDir, "-from", from, "-to", to, "-path", path,
		"-key-snapshot", k.snap, "-key-timestamp", k.ts, "-key-channel", k.channelKey(t, to),
	})
	if err != nil {
		t.Fatalf("promote %s→%s: %v", from, to, err)
	}
}

func verifyOK(t *testing.T, stDir, channel string) {
	t.Helper()
	args := []string{"-state", stDir}
	if channel != "" {
		args = append(args, "-channel", channel)
	}
	if err := runVerify(args); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func resign(t *testing.T, k *testKeys, stDir string) {
	t.Helper()
	if err := runResign([]string{"-state", stDir, "-key-snapshot", k.snap, "-key-timestamp", k.ts}); err != nil {
		t.Fatalf("resign: %v", err)
	}
}

func writeBinary(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// forceExpires re-signs a role file with a new expiry using its key,
// emulating metadata approaching its deadline.
func forceExpires(t *testing.T, k *testKeys, stDir, role string, exp time.Time) {
	t.Helper()
	st := state{dir: stDir}
	env, err := st.loadSigned(role)
	if err != nil {
		t.Fatal(err)
	}
	m, err := tuf.Decode(env, roleTypeOf(role))
	if err != nil {
		t.Fatal(err)
	}
	switch mm := m.(type) {
	case *tuf.Timestamp:
		mm.Expires = exp
	case *tuf.Snapshot:
		mm.Expires = exp
	case *tuf.Targets:
		mm.Expires = exp
	default:
		t.Fatalf("forceExpires: unsupported role %s", role)
	}
	priv, err := loadKey(k.keyFor(t, role))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := tuf.SignCanonical(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.writeSigned(role, signed); err != nil {
		t.Fatal(err)
	}
}

func loadChain(t *testing.T, stDir string) *tuf.Chain {
	t.Helper()
	rootRaw, err := os.ReadFile(filepath.Join(stDir, "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	up, err := tuf.NewUpdater(rootRaw, nil)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := up.Update(dirMirror{state{dir: stDir}})
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

func TestInitRootVerify(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	verifyOK(t, st, "")
	for _, role := range []string{"root.json", "targets.json", "snapshot.json", "timestamp.json",
		"channel-develop.json", "channel-testing.json", "channel-stable.json"} {
		if _, err := os.Stat(filepath.Join(st, role)); err != nil {
			t.Errorf("missing %s: %v", role, err)
		}
	}
}

func TestPublishVerifyRoundtrip(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	bin := writeBinary(t, "cell-linux-amd64", []byte("binary-v1"))
	k.publish(t, st, "develop", bin, "2026110801")
	verifyOK(t, st, "develop")

	chain := loadChain(t, st)
	tg, ok := chain.Target("develop", sha256Hex([]byte("binary-v1"))+".cell-linux-amd64")
	if !ok {
		t.Fatal("target not found in develop chain")
	}
	c, err := tuf.ParseCustom(tg.Custom)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "2026110801" {
		t.Fatalf("custom.version = %q", c.Version)
	}
	if c.ImpactOf("agent_restart") != tuf.LevelRecommended {
		t.Fatalf("impact = %v", c.Impact)
	}
}

func TestPublishIdempotent(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	bin := writeBinary(t, "cell-linux-arm64", []byte("same-bytes"))
	k.publish(t, st, "develop", bin, "2026110802")
	v1 := channelVersion(t, st, "develop")
	k.publish(t, st, "develop", bin, "2026110802")
	if v2 := channelVersion(t, st, "develop"); v2 != v1 {
		t.Fatalf("channel version bumped on identical republish: %d → %d", v1, v2)
	}
	verifyOK(t, st, "develop")
}

func channelVersion(t *testing.T, stDir, ch string) int64 {
	t.Helper()
	env, err := state{dir: stDir}.loadSigned(tuf.ChannelRolePrefix + ch)
	if err != nil {
		t.Fatal(err)
	}
	m, err := tuf.Decode(env, tuf.TargetsRole)
	if err != nil {
		t.Fatal(err)
	}
	return m.MetaVersion()
}

func TestPublishTwoVersions(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	k.publish(t, st, "develop", writeBinary(t, "cell-linux-amd64", []byte("v1")), "2026110810")
	k.publish(t, st, "develop", writeBinary(t, "cell-linux-amd64", []byte("v2")), "2026110811")
	verifyOK(t, st, "develop")
	chain := loadChain(t, st)
	tg, ok := chain.RoleTargets("develop")
	if !ok {
		t.Fatal("no develop role")
	}
	if len(tg.Targets) != 2 {
		t.Fatalf("want 2 targets, got %d", len(tg.Targets))
	}
}

func TestPromoteOneHashTwoChannels(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	bin := writeBinary(t, "cell-linux-amd64", []byte("promo"))
	k.publish(t, st, "develop", bin, "2026110803")
	path := sha256Hex([]byte("promo")) + ".cell-linux-amd64"
	k.promote(t, st, "develop", "testing", path)
	k.promote(t, st, "develop", "stable", path)
	verifyOK(t, st, "")

	chain := loadChain(t, st)
	if err := tuf.CheckPromotion(chain, "develop", "stable", path); err != nil {
		t.Fatalf("CheckPromotion: %v", err)
	}
	if ch, ok := chain.PromotedTo("develop", path); !ok || ch != "stable" {
		t.Fatalf("PromotedTo = %q,%v", ch, ok)
	}
}

func TestResignRefreshesTimestamp(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	k.publish(t, st, "develop", writeBinary(t, "cell-linux-amd64", []byte("rs")), "2026110804")

	forceExpires(t, k, st, tuf.TimestampRole, time.Now().UTC().Add(time.Hour))
	resign(t, k, st)
	env, err := state{dir: st}.loadSigned(tuf.TimestampRole)
	if err != nil {
		t.Fatal(err)
	}
	m, err := tuf.Decode(env, tuf.TimestampRole)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(m.MetaExpires()) < 20*time.Hour {
		t.Fatalf("timestamp expiry not refreshed: %v", m.MetaExpires())
	}
	verifyOK(t, st, "develop")
}

func TestResignRefreshesSnapshotWhenPinnedRoleExpiring(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	k.publish(t, st, "develop", writeBinary(t, "cell-linux-amd64", []byte("rs2")), "2026110805")

	// Channel role expires soon → resign must rebuild snapshot pins.
	forceExpires(t, k, st, tuf.ChannelRolePrefix+"develop", time.Now().UTC().Add(24*time.Hour))
	snapV1 := metaVersion(t, st, tuf.SnapshotRole)
	resign(t, k, st)
	if snapV2 := metaVersion(t, st, tuf.SnapshotRole); snapV2 != snapV1+1 {
		t.Fatalf("snapshot version %d → %d, want +1", snapV1, snapV2)
	}
	verifyOK(t, st, "develop")
}

func metaVersion(t *testing.T, stDir, role string) int64 {
	t.Helper()
	env, err := state{dir: stDir}.loadSigned(role)
	if err != nil {
		t.Fatal(err)
	}
	m, err := tuf.Decode(env, roleTypeOf(role))
	if err != nil {
		t.Fatal(err)
	}
	return m.MetaVersion()
}

func TestVerifyDetectsTamperedArtefact(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	k.publish(t, st, "develop", writeBinary(t, "cell-linux-amd64", []byte("good")), "2026110806")
	good := sha256Hex([]byte("good")) + ".cell-linux-amd64"
	if err := os.WriteFile(filepath.Join(st, "targets", good), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runVerify([]string{"-state", st, "-channel", "develop"})
	if err == nil {
		t.Fatal("verify accepted a tampered artefact")
	}
	if !strings.Contains(err.Error(), good) {
		t.Fatalf("error should name the target: %v", err)
	}
}

func TestVerifyDetectsTamperedMetadata(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	k.publish(t, st, "develop", writeBinary(t, "cell-linux-amd64", []byte("meta")), "2026110807")
	p := filepath.Join(st, "channel-develop.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0o01
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runVerify([]string{"-state", st, "-channel", "develop"}); err == nil {
		t.Fatal("verify accepted tampered metadata")
	}
}

func TestVerifyDetectsBogusSnapshotPin(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	k.publish(t, st, "develop", writeBinary(t, "cell-linux-amd64", []byte("stale")), "2026110808")

	// Validly signed timestamp pinning a hash that is not the snapshot.
	stx := state{dir: st}
	env, err := stx.loadSigned(tuf.TimestampRole)
	if err != nil {
		t.Fatal(err)
	}
	m, err := tuf.Decode(env, tuf.TimestampRole)
	if err != nil {
		t.Fatal(err)
	}
	ts := m.(*tuf.Timestamp)
	fm := ts.Meta[tuf.SnapshotRole]
	fm.Hashes = tuf.Hashes{"sha256": strings.Repeat("00", 32)}
	ts.Meta[tuf.SnapshotRole] = fm
	ts.Version++
	priv, err := loadKey(k.ts)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := tuf.SignCanonical(ts, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := stx.writeSigned(tuf.TimestampRole, signed); err != nil {
		t.Fatal(err)
	}
	if err := runVerify([]string{"-state", st, "-channel", "develop"}); err == nil {
		t.Fatal("verify accepted a timestamp pinning a bogus snapshot")
	}
}

func TestPublishRejectsBadImpact(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	err := runPublish([]string{
		"-state", st, "-channel", "develop",
		"-binary", writeBinary(t, "cell-linux-amd64", []byte("x")), "-version", "2026110809",
		"-key-snapshot", k.snap, "-key-timestamp", k.ts, "-key-channel", k.develop,
		"-impact", "agent_restart=mandatory",
	})
	if err == nil || !strings.Contains(err.Error(), "level") {
		t.Fatalf("want invalid-level error, got %v", err)
	}
}

func TestGenKeyLoadKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.key")
	if err := runGenKey([]string{"-out", p}); err != nil {
		t.Fatal(err)
	}
	priv, err := loadKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("bad key size %d", len(priv))
	}
}

func TestPublishMultiArch(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	amd := writeBinary(t, "cell-linux-amd64", []byte("amd-bytes"))
	arm := writeBinary(t, "cell-linux-arm64", []byte("arm-bytes"))
	k.publishMulti(t, st, "develop", []string{amd, arm}, "2026110901")

	// Metadata-only state: nothing may be written under <state>/targets/.
	if _, err := os.Stat(filepath.Join(st, "targets")); !os.IsNotExist(err) {
		t.Fatalf("publish wrote into state targets dir")
	}
	out := k.outDir(t, st)
	amdPath := sha256Hex([]byte("amd-bytes")) + ".cell-linux-amd64"
	armPath := sha256Hex([]byte("arm-bytes")) + ".cell-linux-arm64"
	for _, p := range []string{amdPath, armPath} {
		if _, err := os.Stat(filepath.Join(out, p)); err != nil {
			t.Fatalf("staged artefact %s: %v", p, err)
		}
	}

	chain := loadChain(t, st)
	tg, ok := chain.RoleTargets("develop")
	if !ok {
		t.Fatal("no develop role")
	}
	if len(tg.Targets) != 2 {
		t.Fatalf("want 2 targets, got %d", len(tg.Targets))
	}

	// -check-binary validates just the new files against the pins.
	if err := runVerify([]string{"-state", st, "-channel", "develop",
		"-check-binary", amd, "-check-binary", arm}); err != nil {
		t.Fatalf("verify -check-binary: %v", err)
	}
	// Full verify (no -check-binary) requires every pinned artefact.
	if err := runVerify([]string{"-state", st, "-channel", "develop"}); err == nil {
		t.Fatal("full verify accepted a metadata-only state dir")
	}
	// -metadata-only is the CI mode for metadata-only state dirs.
	if err := runVerify([]string{"-state", st, "-channel", "develop", "-metadata-only"}); err != nil {
		t.Fatalf("verify -metadata-only: %v", err)
	}
}

func TestPublishMultiIdempotent(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	amd := writeBinary(t, "cell-linux-amd64", []byte("i-amd"))
	arm := writeBinary(t, "cell-linux-arm64", []byte("i-arm"))
	k.publishMulti(t, st, "develop", []string{amd, arm}, "2026110902")
	v1 := channelVersion(t, st, "develop")
	ts1 := metaVersion(t, st, tuf.TimestampRole)
	k.publishMulti(t, st, "develop", []string{amd, arm}, "2026110902")
	if v2 := channelVersion(t, st, "develop"); v2 != v1 {
		t.Fatalf("channel version bumped on identical republish: %d → %d", v1, v2)
	}
	if ts2 := metaVersion(t, st, tuf.TimestampRole); ts2 != ts1 {
		t.Fatalf("timestamp bumped on identical republish: %d → %d", ts1, ts2)
	}
}

func TestCheckBinaryRejectsUnpinnedAndTampered(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	good := writeBinary(t, "cell-linux-amd64", []byte("cb-good"))
	k.publishMulti(t, st, "develop", []string{good}, "2026110903")

	// Binary never published → not pinned.
	rogue := writeBinary(t, "cell-linux-amd64", []byte("rogue"))
	if err := runVerify([]string{"-state", st, "-channel", "develop", "-check-binary", rogue}); err == nil {
		t.Fatal("check-binary accepted an unpinned binary")
	}
	// Published hash, tampered bytes: file named cell-linux-amd64 whose
	// content differs → derived path not pinned → rejection.
	tampered := writeBinary(t, "cell-linux-amd64", []byte("tampered"))
	if err := runVerify([]string{"-state", st, "-channel", "develop", "-check-binary", tampered}); err == nil {
		t.Fatal("check-binary accepted tampered bytes")
	}
	// -check-binary + -metadata-only conflict.
	if err := runVerify([]string{"-state", st, "-metadata-only", "-check-binary", good}); err == nil {
		t.Fatal("metadata-only and check-binary accepted together")
	}
}

func TestPublishRejectsPartialArchFailure(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	amd := writeBinary(t, "cell-linux-amd64", []byte("ok-amd"))
	empty := writeBinary(t, "cell-linux-arm64", nil)
	err := runPublish([]string{
		"-state", st, "-channel", "develop", "-version", "2026110904",
		"-binary", amd, "-binary", empty,
		"-artifacts-out", k.outDir(t, st),
		"-key-snapshot", k.snap, "-key-timestamp", k.ts, "-key-channel", k.develop,
	})
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("want empty-binary error, got %v", err)
	}
	// Metadata must be untouched: initRoot created channel-develop.json at
	// version 1, a successful publish would bump it and add a target.
	if v := channelVersion(t, st, "develop"); v != 1 {
		t.Fatalf("partial publish bumped channel version to %d", v)
	}
	if v := metaVersion(t, st, tuf.TimestampRole); v != 1 {
		t.Fatalf("partial publish bumped timestamp version to %d", v)
	}
}

func TestPromoteExternalArtifact(t *testing.T) {
	k := newTestKeys(t)
	st := newStateDir(t)
	k.initRoot(t, st)
	bin := writeBinary(t, "cell-linux-amd64", []byte("promo-ext"))
	k.publishMulti(t, st, "develop", []string{bin}, "2026110905")
	path := sha256Hex([]byte("promo-ext")) + ".cell-linux-amd64"

	// Metadata-only state (no targets/): promote with -artifact.
	if _, err := os.Stat(filepath.Join(st, "targets")); !os.IsNotExist(err) {
		t.Fatal("publishMulti should not write state targets")
	}
	if err := runPromote([]string{
		"-state", st, "-from", "develop", "-to", "stable", "-path", path,
		"-artifact", bin,
		"-key-snapshot", k.snap, "-key-timestamp", k.ts, "-key-channel", k.stable,
	}); err != nil {
		t.Fatalf("promote -artifact: %v", err)
	}
	chain := loadChain(t, st)
	if err := tuf.CheckPromotion(chain, "develop", "stable", path); err != nil {
		t.Fatalf("CheckPromotion: %v", err)
	}

	// Wrong bytes → rejection.
	if err := runPromote([]string{
		"-state", st, "-from", "develop", "-to", "testing", "-path", path,
		"-artifact", writeBinary(t, "promo.bin.cell-linux-amd64", []byte("other-bytes")),
		"-key-snapshot", k.snap, "-key-timestamp", k.ts, "-key-channel", k.testing,
	}); err == nil || !strings.Contains(err.Error(), "pinned hash") {
		t.Fatalf("want pinned-hash mismatch, got %v", err)
	}
}

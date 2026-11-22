package tuf

import (
	"bytes"
	"testing"
)

func TestBundleRoundtrip(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	artifact := []byte("air-gapped release")
	tg := makeTarget(t, artifact, Custom{Version: "3.0.0"})
	p.PublishTargets(map[string]Target{"v3.0.0/cell-linux-amd64": tg}, nil, nil)

	// Writer: all metadata + the artefact.
	bw := NewBundleWriter()
	for _, role := range []string{RootRole, TimestampRole, SnapshotRole, TargetsRole} {
		bw.AddMeta(role, p.files[role])
	}
	bw.AddTarget("v3.0.0/cell-linux-amd64", artifact)
	var buf bytes.Buffer
	if err := bw.Write(&buf); err != nil {
		t.Fatal(err)
	}

	// Reader: fresh trust root (operator-supplied), update via bundle.
	b, err := ReadBundle(&buf)
	if err != nil {
		t.Fatal(err)
	}
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := u.Update(b)
	if err != nil {
		t.Fatalf("bundle update: %v", err)
	}
	if err := b.VerifyTarget(chain, "", "v3.0.0/cell-linux-amd64"); err != nil {
		t.Fatalf("bundle verify: %v", err)
	}
}

func TestBundleTamperedArtefact(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	artifact := []byte("release bytes")
	tg := makeTarget(t, artifact, Custom{Version: "3.1.0"})
	p.PublishTargets(map[string]Target{"v3.1.0/cell": tg}, nil, nil)

	bw := NewBundleWriter()
	for _, role := range []string{RootRole, TimestampRole, SnapshotRole, TargetsRole} {
		bw.AddMeta(role, p.files[role])
	}
	bw.AddTarget("v3.1.0/cell", []byte("tampered bytes!!"))
	var buf bytes.Buffer
	if err := bw.Write(&buf); err != nil {
		t.Fatal(err)
	}
	b, err := ReadBundle(&buf)
	if err != nil {
		t.Fatal(err)
	}
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := u.Update(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.VerifyTarget(chain, "", "v3.1.0/cell"); err == nil {
		t.Fatal("tampered artefact in bundle accepted")
	}
}

func TestBundleMissingMeta(t *testing.T) {
	keys := newTestKeys(t)
	p := newPublisher(t, keys)
	p.PublishTargets(nil, nil, nil)
	bw := NewBundleWriter()
	bw.AddMeta(RootRole, p.files[RootRole])
	bw.AddMeta(TimestampRole, p.files[TimestampRole])
	// snapshot/targets deliberately missing
	var buf bytes.Buffer
	if err := bw.Write(&buf); err != nil {
		t.Fatal(err)
	}
	b, err := ReadBundle(&buf)
	if err != nil {
		t.Fatal(err)
	}
	u, err := NewUpdater(p.files[RootRole], mustNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Update(b); err == nil {
		t.Fatal("bundle missing snapshot accepted")
	}
}

func TestBundleUnsafePath(t *testing.T) {
	bw := NewBundleWriter()
	bw.AddTarget("../escape", []byte("x"))
	if err := bw.Write(&bytes.Buffer{}); err == nil {
		t.Fatal("unsafe target path accepted")
	}
}

package tuf

import (
	"archive/tar"
	"fmt"
	"io"
	"strings"
)

// Offline bundle: a tar archive carrying the full signed metadata set
// plus the target artefacts, for air-gapped cells. The bundle is an
// untrusted transport — verification is identical to the online path:
// the operator still supplies the trusted root (it is NOT taken from
// the bundle), then timestamp → snapshot → targets → channels → target
// hashes all verify through Updater/Chain.
//
// Layout inside the tar:
//
//	tuf/root.json
//	tuf/timestamp.json
//	tuf/snapshot.json
//	tuf/targets.json
//	tuf/channel-develop.json ... (role files, RoleFile names)
//	tuf/targets/<path>          artefacts, path as pinned in targets
const (
	bundleMetaDir   = "tuf"
	bundleTargetDir = "tuf/targets"
)

// BundleWriter accumulates metadata and artefacts, then emits the tar.
type BundleWriter struct {
	meta    map[string][]byte // role → file bytes
	targets map[string][]byte // target path → bytes
}

func NewBundleWriter() *BundleWriter {
	return &BundleWriter{meta: map[string][]byte{}, targets: map[string][]byte{}}
}

// AddMeta stores a signed role file (raw JSON envelope) under role.
func (b *BundleWriter) AddMeta(role string, file []byte) {
	b.meta[role] = append([]byte(nil), file...)
}

// AddTarget stores an artefact under the path pinned in targets.
func (b *BundleWriter) AddTarget(path string, data []byte) {
	b.targets[path] = append([]byte(nil), data...)
}

// Write emits the bundle into w.
func (b *BundleWriter) Write(w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close()
	for role, file := range b.meta {
		hdr := &tar.Header{
			Name:     bundleMetaDir + "/" + roleFileName(role),
			Mode:     0o444,
			Size:     int64(len(file)),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(file); err != nil {
			return err
		}
	}
	for path, data := range b.targets {
		if !safeTargetPath(path) {
			return fmt.Errorf("tuf: bundle: unsafe target path %q", path)
		}
		hdr := &tar.Header{
			Name:     bundleTargetDir + "/" + path,
			Mode:     0o444,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// Bundle is a read bundle implementing Fetcher; artefacts stream from
// memory with the same pinned-hash checks as the HTTP path.
type Bundle struct {
	meta    map[string][]byte
	targets map[string][]byte
}

// ReadBundle parses a tar bundle produced by BundleWriter. It does not
// verify anything — pass it to Updater.Update like any Fetcher.
func ReadBundle(r io.Reader) (*Bundle, error) {
	tr := tar.NewReader(r)
	b := &Bundle{meta: map[string][]byte{}, targets: map[string][]byte{}}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		switch {
		case strings.HasPrefix(hdr.Name, bundleTargetDir+"/"):
			path := strings.TrimPrefix(hdr.Name, bundleTargetDir+"/")
			if !safeTargetPath(path) {
				return nil, fmt.Errorf("tuf: bundle: unsafe target path %q", path)
			}
			b.targets[path] = data
		case strings.HasPrefix(hdr.Name, bundleMetaDir+"/") && strings.HasSuffix(hdr.Name, ".json"):
			role := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, bundleMetaDir+"/"), ".json")
			b.meta[nameToChannel(role)] = data
		}
	}
	return b, nil
}

// Fetch implements Fetcher (metadata only).
func (b *Bundle) Fetch(role string) ([]byte, error) {
	data, ok := b.meta[role]
	if !ok {
		return nil, fmt.Errorf("tuf: bundle has no metadata for %q", role)
	}
	return data, nil
}

// Target returns artefact bytes by pinned path.
func (b *Bundle) Target(path string) ([]byte, bool) {
	data, ok := b.targets[path]
	return data, ok
}

// VerifyTarget checks artefact bytes pinned in chain for channel.
func (b *Bundle) VerifyTarget(chain *Chain, channel, path string) error {
	tg, ok := chain.Target(channel, path)
	if !ok {
		return fmt.Errorf("tuf: bundle: target %q not found in channel %q", path, channel)
	}
	data, ok := b.targets[path]
	if !ok {
		return fmt.Errorf("tuf: bundle: artefact %q missing", path)
	}
	if int64(len(data)) != tg.Length {
		return fmt.Errorf("tuf: bundle: artefact %q length %d != pinned %d", path, len(data), tg.Length)
	}
	return tg.Hashes.Check(data)
}

// BundleFetcher couples a Bundle with a chain for HTTPMirror-like use.
type BundleFetcher struct{ Bundle *Bundle }

// Download verifies in-bundle artefacts against the pinned target.
func (f *BundleFetcher) Download(_ string, t *Target) ([]byte, error) {
	for _, data := range f.Bundle.targets {
		if int64(len(data)) == t.Length && t.Hashes.Check(data) == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("tuf: bundle: artefact matching pinned target not found")
}

func safeTargetPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return false
		}
	}
	return true
}

// roleFileName maps a role to its file name inside the bundle
// ("root.json", "channel-develop.json").
func roleFileName(role string) string {
	return strings.ReplaceAll(role, "/", "-") + ".json"
}

// nameToChannel inverts channelToName for bundle role files.
func nameToChannel(name string) string {
	if strings.HasPrefix(name, "channel-") {
		return ChannelRolePrefix + strings.TrimPrefix(name, "channel-")
	}
	return name
}

// MetaRoles returns the role names present in the bundle (for CLI listing).
func (b *Bundle) MetaRoles() []string {
	out := make([]string, 0, len(b.meta))
	for r := range b.meta {
		out = append(out, r)
	}
	return out
}

package tuf

import (
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// HTTPMirror is an online Fetcher for the CDN layout:
//
//	<Base>/tuf/<role>.json      metadata
//	<Base>/tuf/targets/<path>   targets (via DownloadFetcher)
type HTTPMirror struct {
	Base   string // e.g. https://cdn.unistack.org
	Client *http.Client
	MaxAge time.Duration // reserved; 0 = no cache policy
}

// NewHTTPMirror points a mirror client at a base URL (no trailing /).
func NewHTTPMirror(base string, client *http.Client) *HTTPMirror {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &HTTPMirror{Base: strings.TrimRight(base, "/"), Client: client}
}

// Fetch implements Fetcher.
func (m *HTTPMirror) Fetch(role string) ([]byte, error) {
	u := m.Base + "/tuf/" + RoleFile(role)
	resp, err := m.Client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("tuf: %s: not found on mirror", role)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tuf: %s: mirror returned %s", role, resp.Status)
	}
	// Metadata files are small; cap defensively.
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// DownloadFetcher for targets pinned in this mirror, with an optional
// in-metadata mirror list (custom.mirrors) taking precedence.
func (m *HTTPMirror) ForTarget(t *Target, seed string) (*DownloadFetcher, error) {
	ms, err := MirrorsOf(m.Base, t)
	if err != nil {
		return nil, err
	}
	return &DownloadFetcher{
		Mirrors: ms,
		Seed:    seed,
		Get: func(u string) (io.ReadCloser, error) {
			resp, err := m.Client.Get(u)
			if err != nil {
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return nil, fmt.Errorf("tuf: %s: mirror returned %s", u, resp.Status)
			}
			return resp.Body, nil
		},
	}, nil
}

// Mirror is one download endpoint. The list lives in signed metadata
// (target custom.mirrors), so mirrors are as trusted as the channel
// key that signed the target.
type Mirror struct {
	URL     string `json:"url"`
	Weight  int    `json:"weight,omitempty"`  // relative share, default 1
	Purpose string `json:"purpose,omitempty"` // "" (any), "cdn", "origin", "lan"
}

// MirrorSet is the weighted mirror list of one artefact.
type MirrorSet []Mirror

// MirrorsOf extracts mirrors from a target's custom metadata. The
// result always contains at least one entry: when custom has no
// mirrors, a fallback (base URL + "/" + target path) is synthesised,
// matching the CDN layout "…/tuf/targets/<file>".
func MirrorsOf(baseURL string, t *Target) (MirrorSet, error) {
	c, err := ParseCustom(t.Custom)
	if err != nil {
		return nil, err
	}
	out := make(MirrorSet, 0, len(c.Mirrors))
	for _, m := range c.Mirrors {
		if strings.TrimSpace(m.URL) == "" {
			return nil, fmt.Errorf("tuf: target has mirror with empty url")
		}
		if _, err := url.Parse(m.URL); err != nil {
			return nil, fmt.Errorf("tuf: mirror url %q: %w", m.URL, err)
		}
		if m.Weight < 0 {
			return nil, fmt.Errorf("tuf: mirror %q has negative weight", m.URL)
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		u, err := url.JoinPath(baseURL, "tuf", "targets")
		if err != nil {
			return nil, err
		}
		out = append(out, Mirror{URL: u})
	}
	return out, nil
}

// Ordered returns the mirrors in preference order for this artefact:
// weighted deterministic shuffle (the same target always yields the
// same order for a given client seed, so a fleet spreads across
// mirrors without a coordinator).
func (ms MirrorSet) Ordered(seed string) []Mirror {
	total := 0
	for _, m := range ms {
		w := m.Weight
		if w < 1 {
			w = 1
		}
		total += w
	}
	out := make([]Mirror, 0, len(ms)*2)
	// Build the weighted list deterministically, then stable-sort by
	// hash(seed|index) so each artefact pins a client to a mirror
	// subset, not the whole fleet to mirror #1.
	type entry struct {
		m Mirror
		k uint64
	}
	ents := make([]entry, 0, total)
	for idx, m := range ms {
		w := m.Weight
		if w < 1 {
			w = 1
		}
		for i := 0; i < w; i++ {
			h := fnv.New64a()
			h.Write([]byte(seed))
			h.Write([]byte{0})
			fmt.Fprintf(h, "%d", idx)
			h.Write([]byte{byte(i)})
			ents = append(ents, entry{m: m, k: h.Sum64()})
		}
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].k < ents[j].k })
	seen := map[string]bool{}
	for _, e := range ents {
		key := e.m.Purpose + "\x00" + e.m.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e.m)
	}
	return out
}

// DownloadFetcher streams a target through the mirror set, checking
// pinned hashes on the fly; mirrors are tried in preference order and
// a mid-stream failure falls over to the next mirror.
type DownloadFetcher struct {
	Mirrors MirrorSet
	Seed    string
	Get     func(url string) (io.ReadCloser, error)
}

// Download returns the verified bytes of path as pinned in target t.
func (d *DownloadFetcher) Download(path string, t *Target) ([]byte, error) {
	if d.Get == nil {
		return nil, fmt.Errorf("tuf: DownloadFetcher.Get is not set")
	}
	var lastErr error
	for _, m := range d.Mirrors.Ordered(d.Seed) {
		u, err := url.JoinPath(m.URL, path)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := d.downloadOne(u, t)
		if err == nil {
			return data, nil
		}
		lastErr = fmt.Errorf("mirror %s: %w", m.URL, err)
	}
	return nil, lastErr
}

func (d *DownloadFetcher) downloadOne(u string, t *Target) ([]byte, error) {
	rc, err := d.Get(u)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, t.Length+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != t.Length {
		return nil, fmt.Errorf("tuf: download size %d != pinned %d", len(data), t.Length)
	}
	if err := t.Hashes.Check(data); err != nil {
		return nil, err
	}
	return data, nil
}

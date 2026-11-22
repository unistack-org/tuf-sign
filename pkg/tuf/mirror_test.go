package tuf

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMirrorsOfFallback(t *testing.T) {
	tg := Target{} // no custom
	ms, err := MirrorsOf("https://cdn.unistack.org", &tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].URL != "https://cdn.unistack.org/tuf/targets" {
		t.Fatalf("fallback mirror = %+v", ms)
	}
}

func TestMirrorOrderDeterministicSpread(t *testing.T) {
	ms := MirrorSet{
		{URL: "https://a", Weight: 3},
		{URL: "https://b", Weight: 1},
		{URL: "https://c"},
	}
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		seed := fmt.Sprintf("cell-%d", i)
		ord := ms.Ordered(seed)
		if len(ord) != 3 {
			t.Fatalf("ordered len = %d", len(ord))
		}
		// stable per seed
		ord2 := ms.Ordered(seed)
		for j := range ord {
			if ord[j].URL != ord2[j].URL {
				t.Fatalf("order not deterministic for seed %s", seed)
			}
		}
		seen[ord[0].URL]++
	}
	// Heaviest mirror should be first most often, but not for every seed.
	if seen["https://a"] < seen["https://b"] {
		t.Fatalf("weight ignored: %v", seen)
	}
	if seen["https://a"] == 200 {
		t.Fatalf("no spread across mirrors: %v", seen)
	}
}

func TestDownloadFetcherMirrorFailover(t *testing.T) {
	artifact := []byte("cell binary payload")
	tg := Target{
		Length: int64(len(artifact)),
		Hashes: Hashes{hashAlgoSHA256: sha256Hex(artifact)},
	}
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		switch r.URL.Path {
		case "/bad/tuf/targets/v1/cell":
			io.WriteString(w, "corrupted data that will not match the pin!!")
		case "/dead/tuf/targets/v1/cell":
			w.WriteHeader(http.StatusInternalServerError)
		case "/good/tuf/targets/v1/cell":
			w.Write(artifact)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	ms := MirrorSet{
		{URL: srv.URL + "/dead/tuf/targets"},
		{URL: srv.URL + "/bad/tuf/targets"},
		{URL: srv.URL + "/good/tuf/targets"},
	}
	d := &DownloadFetcher{Mirrors: ms, Seed: "test", Get: func(u string) (io.ReadCloser, error) {
		resp, err := http.Get(u)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("status %s", resp.Status)
		}
		return resp.Body, nil
	}}
	// Deterministic order: every mirror ahead of the good one must have
	// been tried (failover) before the good mirror served the artefact.
	ord := ms.Ordered("test")
	got, err := d.Download("v1/cell", &tg)
	if err != nil {
		t.Fatalf("download with failover: %v", err)
	}
	if !bytes.Equal(got, artifact) {
		t.Fatal("downloaded bytes mismatch")
	}
	for _, m := range ord {
		if m.URL == srv.URL+"/good/tuf/targets" {
			break
		}
		want := m.URL + "/v1/cell"
		found := false
		for _, h := range hits {
			if h == want[len(srv.URL):] {
				found = true
			}
		}
		if !found {
			t.Fatalf("mirror %s skipped before good mirror; hits=%v", m.URL, hits)
		}
	}
}

func TestHTTPMirrorFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tuf/root.json" {
			io.WriteString(w, `{"signed":{},"signatures":[]}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	m := NewHTTPMirror(srv.URL, srv.Client())
	raw, err := m.Fetch(RootRole)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("signatures")) {
		t.Fatalf("body = %s", raw)
	}
	if _, err := m.Fetch(SnapshotRole); err == nil {
		t.Fatal("404 accepted")
	}
}

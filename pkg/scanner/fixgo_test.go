package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/offline"
)

func fixGoProxy(t *testing.T, mods map[string]string, requests *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, ok := mods[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The x/* modules raise their minimum Go shortly after each Go release: the fix exists, but only in a version that needs a
// newer Go than the graded module supports. The go directive of the fixed version's go.mod is what tells.
func TestResolveFixGoRequirements(t *testing.T) {
	var n atomic.Int32
	srv := fixGoProxy(t, map[string]string{
		"/golang.org/x/image/@v/v0.46.0.mod": "module golang.org/x/image\n\ngo 1.26.0\n\nrequire golang.org/x/text v0.42.0\n",
		"/golang.org/x/image/@v/v0.38.0.mod": "module golang.org/x/image\n\ngo 1.24.0\n",
	}, &n)
	vulns := []Vulnerability{
		{ID: "GO-1", FixedVersion: "v0.46.0"},
		{ID: "GO-2", FixedVersion: "0.46.0"}, // the same fix, written without the v: one lookup
		{ID: "GO-3", FixedVersion: "v0.38.0"},
		{ID: "GO-4"},                         // no fix: nothing to ask
		{ID: "GO-5", FixedVersion: "v9.9.9"}, // the proxy has no such version: unknown, never invented
	}
	ResolveFixGoRequirements(context.Background(), FixDateOptions{ProxyURL: srv.URL, Timeout: 5 * time.Second}, "golang.org/x/image", vulns)
	want := []string{"1.26.0", "1.26.0", "1.24.0", "", ""}
	for i, w := range want {
		if vulns[i].FixRequiresGo != w {
			t.Errorf("%s: FixRequiresGo = %q, want %q", vulns[i].ID, vulns[i].FixRequiresGo, w)
		}
	}
	if got := n.Load(); got != 3 {
		t.Errorf("%d proxy requests, want 3 (one per distinct fixed version that exists or is asked)", got)
	}
}

func TestResolveFixGoRequirements_FailuresAndOfflineLeaveItEmpty(t *testing.T) {
	var n atomic.Int32
	srv := fixGoProxy(t, map[string]string{"/m/@v/v1.0.1.mod": "module m\n\nthis is not valid ((\n"}, &n)
	vulns := []Vulnerability{{ID: "GO-1", FixedVersion: "v1.0.1", FixRequiresGo: "stale"}}
	ResolveFixGoRequirements(context.Background(), FixDateOptions{ProxyURL: srv.URL}, "m", vulns)
	if vulns[0].FixRequiresGo != "" {
		t.Errorf("an unreadable go.mod leaves it unknown: %q", vulns[0].FixRequiresGo)
	}
	offline.Enable()
	t.Cleanup(offline.Disable)
	n.Store(0)
	v2 := []Vulnerability{{ID: "GO-2", FixedVersion: "v1.0.1"}}
	ResolveFixGoRequirements(context.Background(), FixDateOptions{ProxyURL: srv.URL}, "m", v2)
	if n.Load() != 0 || v2[0].FixRequiresGo != "" {
		t.Errorf("offline: %d requests, %q", n.Load(), v2[0].FixRequiresGo)
	}
}

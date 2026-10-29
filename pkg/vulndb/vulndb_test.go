package vulndb

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const sampleIndex = `[
 {"path":"golang.org/x/net","vulns":[{"id":"GO-2026-0002","modified":"2026-06-25T22:34:34Z","fixed":"0.17.0"},{"id":"GO-2025-0001","modified":"2025-01-02T03:04:05Z","fixed":"0.10.0"}]},
 {"path":"antrea.io/antrea","vulns":[{"id":"GO-2026-5579","modified":"2026-06-25T22:34:34Z"},{"id":"GO-2026-5579","modified":"2026-06-25T22:34:34Z","fixed":"1.11.0"},{"id":"GO-2026-5579","modified":"2026-06-25T22:34:34Z"}]},
 {"path":"stdlib","vulns":[{"id":"GO-2021-0067","modified":"2024-05-20T16:03:47Z","fixed":"1.16.1"}]}
]`

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	return b.Bytes()
}

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseIndex_GzipAndPlain(t *testing.T) {
	for name, data := range map[string][]byte{"gzip": gz(t, sampleIndex), "plain": []byte(sampleIndex)} {
		idx, err := ParseIndex(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(idx.Modules) != 3 || len(idx.Modules["golang.org/x/net"]) != 2 || idx.Modules["golang.org/x/net"][0].Fixed != "0.17.0" {
			t.Errorf("%s: %+v", name, idx.Modules)
		}
	}
	if _, err := ParseIndex([]byte("not json")); err == nil {
		t.Error("want an error for garbage")
	}
	if _, err := ParseIndex([]byte{0x1f, 0x8b, 0x00}); err == nil {
		t.Error("want an error for a broken gzip stream")
	}
}

func TestChangedSince(t *testing.T) {
	idx, _ := ParseIndex([]byte(sampleIndex))
	if got := idx.ChangedSince(ts("2026-01-01T00:00:00Z")); !reflect.DeepEqual(got, []string{"antrea.io/antrea", "golang.org/x/net"}) {
		t.Errorf("ChangedSince = %v", got)
	}
	if got := idx.ChangedSince(ts("2026-06-25T22:34:34Z")); len(got) != 0 {
		t.Errorf("strictly after: %v", got)
	}
	if got := idx.ChangedSince(ts("2020-01-01T00:00:00Z")); len(got) != 3 {
		t.Errorf("all: %v", got)
	}
	changes := idx.ChangesSince(ts("2026-01-01T00:00:00Z"))
	if len(changes) != 2 || changes[0].Module != "antrea.io/antrea" || !reflect.DeepEqual(changes[0].IDs, []string{"GO-2026-5579"}) || !reflect.DeepEqual(changes[1].IDs, []string{"GO-2026-0002"}) {
		t.Errorf("ChangesSince = %+v", changes)
	}
}

func TestFingerprint(t *testing.T) {
	idx, _ := ParseIndex([]byte(sampleIndex))
	a := idx.Fingerprint([]string{"golang.org/x/net", "stdlib"})
	if a == "" || a != idx.Fingerprint([]string{"stdlib", "golang.org/x/net", "stdlib"}) {
		t.Error("the fingerprint must not depend on the order or repeats of the modules")
	}
	if a != idx.Fingerprint([]string{"golang.org/x/net", "stdlib", "example.com/no-advisories"}) {
		t.Error("a module with no advisory must not change the fingerprint")
	}
	if a == idx.Fingerprint([]string{"golang.org/x/net"}) {
		t.Error("another module with advisories must change it")
	}

	changed := strings.Replace(sampleIndex, "2026-06-25T22:34:34Z\",\"fixed\":\"0.17.0", "2026-07-01T00:00:00Z\",\"fixed\":\"0.17.0", 1)
	idx2, _ := ParseIndex([]byte(changed))
	if idx2.Fingerprint([]string{"golang.org/x/net"}) == idx.Fingerprint([]string{"golang.org/x/net"}) {
		t.Error("a modified advisory must change the fingerprint of its module")
	}
	if idx2.Fingerprint([]string{"stdlib"}) != idx.Fingerprint([]string{"stdlib"}) {
		t.Error("and only of its module")
	}
	removed := strings.Replace(sampleIndex, `,{"id":"GO-2025-0001","modified":"2025-01-02T03:04:05Z","fixed":"0.10.0"}`, "", 1)
	idx3, _ := ParseIndex([]byte(removed))
	if idx3.Fingerprint([]string{"golang.org/x/net"}) == idx.Fingerprint([]string{"golang.org/x/net"}) {
		t.Error("a removed advisory must change the fingerprint, though no timestamp shows it")
	}
}

func server(t *testing.T, dbModified string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case ModulesIndexPath:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(gz(t, sampleIndex))
		case DBIndexPath:
			_, _ = w.Write([]byte(`{"modified":"` + dbModified + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestClient_FetchIndexAndChangedModules(t *testing.T) {
	var hits atomic.Int32
	srv := server(t, "2026-10-21T00:27:29Z", &hits)
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	ctx := context.Background()

	idx, err := c.FetchIndex(ctx)
	if err != nil || len(idx.Modules) != 3 || !idx.DBModified.Equal(ts("2026-10-21T00:27:29Z")) {
		t.Fatalf("FetchIndex = %+v, %v", idx, err)
	}

	// the database changed after the timestamp: the index is read and the changes returned
	hits.Store(0)
	changes, dbm, idx, err := c.ChangedModules(ctx, ts("2026-01-01T00:00:00Z"))
	if err != nil || len(changes) != 2 || idx == nil || !dbm.Equal(ts("2026-10-21T00:27:29Z")) || hits.Load() != 2 {
		t.Fatalf("ChangedModules = %+v, %v, %v, %v (%d requests)", changes, dbm, idx != nil, err, hits.Load())
	}

	// nothing changed since the timestamp: only db.json is read
	hits.Store(0)
	changes, _, idx, err = c.ChangedModules(ctx, ts("2026-10-21T00:27:29Z"))
	if err != nil || len(changes) != 0 || idx != nil || hits.Load() != 1 {
		t.Fatalf("unchanged: %+v, %v, %v (%d requests)", changes, idx != nil, err, hits.Load())
	}
}

func TestClient_Errors(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := (&Client{BaseURL: srv.URL}).FetchIndex(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("err = %v", err)
	}
	if _, err := (&Client{BaseURL: srv.URL}).DBModified(context.Background()); err == nil {
		t.Error("want an error")
	}
}

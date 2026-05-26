package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// newTestCache returns a maintainerCache backed by a temporary directory that
// is automatically cleaned up when the test finishes.
func newTestCache(t *testing.T, ttl time.Duration) *maintainerCache {
	t.Helper()
	dir := t.TempDir()
	c := newMaintainerCache(dir, ttl)
	return c
}

// TestMaintainerCache_HitWithinTTL verifies that a value written to the cache
// is returned on a subsequent Get within the TTL window.
func TestMaintainerCache_HitWithinTTL(t *testing.T) {
	c := newTestCache(t, time.Hour)

	const url = "https://api.github.com/repos/golang/go"
	body := []byte(`{"name":"go","stars":50000}`)

	if err := c.Put(url, body); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, hit, err := c.Get(url)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !hit {
		t.Fatal("expected cache hit, got miss")
	}
	if string(got) != string(body) {
		t.Errorf("body mismatch: got %q, want %q", got, body)
	}
}

// TestMaintainerCache_MissPastTTL verifies that an entry is treated as a miss
// once the TTL has elapsed. The clock is injected via nowFunc so no real time
// passes during the test.
func TestMaintainerCache_MissPastTTL(t *testing.T) {
	ttl := time.Hour
	c := newTestCache(t, ttl)

	// Pin the clock to "now" when writing.
	epoch := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	c.nowFunc = func() time.Time { return epoch }

	const url = "https://api.github.com/repos/golang/tools"
	body := []byte(`{"name":"tools","stars":100}`)

	if err := c.Put(url, body); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Advance clock past the TTL.
	c.nowFunc = func() time.Time { return epoch.Add(ttl + time.Second) }

	_, hit, err := c.Get(url)
	if err != nil {
		t.Fatalf("Get after TTL expiry: %v", err)
	}
	if hit {
		t.Fatal("expected cache miss after TTL expiry, got hit")
	}
}

// TestMaintainerCache_MissNotFound verifies that a Get for an uncached URL
// returns (nil, false, nil) — a normal miss without error.
func TestMaintainerCache_MissNotFound(t *testing.T) {
	c := newTestCache(t, time.Hour)

	const url = "https://api.github.com/repos/missing/pkg"
	got, hit, err := c.Get(url)
	if err != nil {
		t.Fatalf("Get on cold cache: %v", err)
	}
	if hit {
		t.Fatal("expected miss on cold cache, got hit")
	}
	if got != nil {
		t.Errorf("expected nil body on miss, got %q", got)
	}
}

// TestMaintainerCache_ConcurrentWritersSameKey verifies that concurrent writers
// racing on the same cache key produce a valid, complete file — the
// write-then-rename atomic pattern must prevent torn reads.
func TestMaintainerCache_ConcurrentWritersSameKey(t *testing.T) {
	c := newTestCache(t, time.Hour)

	const url = "https://api.github.com/repos/concurrent/test"
	body := []byte(`{"name":"concurrent","stars":42}`)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = c.Put(url, body)
		}()
	}
	wg.Wait()

	// After all goroutines complete, the file must be a valid cache entry.
	got, hit, err := c.Get(url)
	if err != nil {
		t.Fatalf("Get after concurrent writes: %v", err)
	}
	if !hit {
		t.Fatal("expected cache hit after concurrent writes")
	}
	if string(got) != string(body) {
		t.Errorf("body mismatch after concurrent writes: got %q, want %q", got, body)
	}
}

// TestMaintainerCache_DifferentURLsDifferentKeys verifies that two URLs hash to
// different files and do not collide.
func TestMaintainerCache_DifferentURLsDifferentKeys(t *testing.T) {
	c := newTestCache(t, time.Hour)

	url1 := "https://api.github.com/repos/owner/repo1"
	url2 := "https://api.github.com/repos/owner/repo2"
	body1 := []byte(`{"name":"repo1"}`)
	body2 := []byte(`{"name":"repo2"}`)

	if err := c.Put(url1, body1); err != nil {
		t.Fatalf("Put url1: %v", err)
	}
	if err := c.Put(url2, body2); err != nil {
		t.Fatalf("Put url2: %v", err)
	}

	got1, hit1, err := c.Get(url1)
	if err != nil || !hit1 || string(got1) != string(body1) {
		t.Errorf("url1: hit=%v err=%v body=%q, want true nil %q", hit1, err, got1, body1)
	}

	got2, hit2, err := c.Get(url2)
	if err != nil || !hit2 || string(got2) != string(body2) {
		t.Errorf("url2: hit=%v err=%v body=%q, want true nil %q", hit2, err, got2, body2)
	}
}

// TestMaintainerCache_DisabledOnBadDir verifies that a cache pointing to an
// unwritable directory logs a warning and then behaves as a no-op: Get returns
// miss, Put returns nil (no error), and the scanner is not aborted.
func TestMaintainerCache_DisabledOnBadDir(t *testing.T) {
	// Use a path that cannot exist because its parent is a file, not a directory.
	parent := filepath.Join(t.TempDir(), "file-not-dir")
	if err := os.WriteFile(parent, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	badDir := filepath.Join(parent, "subdir")

	c := newMaintainerCache(badDir, time.Hour)

	// ensureDir should fail and disable the cache.
	ok := c.ensureDir()
	if ok {
		t.Fatal("ensureDir should return false for unwritable path")
	}
	if !c.isDisabled() {
		t.Fatal("cache should be disabled after ensureDir failure")
	}

	// Put must be a no-op — not an error.
	if err := c.Put("https://api.github.com/repos/x/y", []byte(`{}`)); err != nil {
		t.Errorf("Put on disabled cache returned unexpected error: %v", err)
	}

	// Get must return a miss — not an error.
	got, hit, err := c.Get("https://api.github.com/repos/x/y")
	if err != nil {
		t.Errorf("Get on disabled cache returned error: %v", err)
	}
	if hit {
		t.Error("Get on disabled cache should return miss")
	}
	if got != nil {
		t.Errorf("Get on disabled cache should return nil body, got %q", got)
	}
}

// TestMaintainerCache_CacheKey verifies that the same URL always produces the
// same cache key and different URLs produce different keys.
func TestMaintainerCache_CacheKey(t *testing.T) {
	url := "https://api.github.com/repos/owner/repo"
	k1 := cacheKey(url)
	k2 := cacheKey(url)
	if k1 != k2 {
		t.Errorf("cacheKey not deterministic: %q != %q", k1, k2)
	}

	other := cacheKey("https://api.github.com/repos/other/repo")
	if k1 == other {
		t.Error("different URLs produced the same cache key")
	}
}

// TestMaintainerCache_GzipRoundTrip verifies that gzipBytes and gunzip are
// inverse operations and that no data is lost.
func TestMaintainerCache_GzipRoundTrip(t *testing.T) {
	original := []byte(`{"name":"go","stars":50000,"description":"The Go programming language"}`)
	compressed, err := gzipBytes(original)
	if err != nil {
		t.Fatalf("gzipBytes: %v", err)
	}
	if len(compressed) == 0 {
		t.Fatal("gzipBytes returned empty result")
	}

	recovered, err := gunzip(compressed)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	if string(recovered) != string(original) {
		t.Errorf("round-trip mismatch: got %q, want %q", recovered, original)
	}
}

// TestMaintainerCache_OverwriteRefreshesTTL verifies that a Put after TTL expiry
// refreshes the entry so the next Get within TTL returns a hit.
func TestMaintainerCache_OverwriteRefreshesTTL(t *testing.T) {
	ttl := time.Hour
	c := newTestCache(t, ttl)

	epoch := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	c.nowFunc = func() time.Time { return epoch }

	const url = "https://api.github.com/repos/refresh/test"
	old := []byte(`{"name":"old"}`)
	if err := c.Put(url, old); err != nil {
		t.Fatalf("Put old: %v", err)
	}

	// Advance clock past TTL — entry is now stale.
	c.nowFunc = func() time.Time { return epoch.Add(ttl + time.Minute) }

	// Overwrite with fresh content at the new "now".
	fresh := []byte(`{"name":"fresh"}`)
	if err := c.Put(url, fresh); err != nil {
		t.Fatalf("Put fresh: %v", err)
	}

	// Should be a hit because we just wrote it.
	got, hit, err := c.Get(url)
	if err != nil || !hit {
		t.Fatalf("expected hit after refresh; hit=%v err=%v", hit, err)
	}
	if string(got) != string(fresh) {
		t.Errorf("body after refresh: got %q, want %q", got, fresh)
	}
}

// TestMaintainerCache_ConcurrentGetPut verifies that concurrent readers and
// writers on different keys do not interfere with each other.
func TestMaintainerCache_ConcurrentGetPut(t *testing.T) {
	c := newTestCache(t, time.Hour)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n * 2)

	for i := 0; i < n; i++ {
		url := fmt.Sprintf("https://api.github.com/repos/org/repo%d", i)
		body := []byte(fmt.Sprintf(`{"name":"repo%d"}`, i))

		// Writer
		go func(u string, b []byte) {
			defer wg.Done()
			_ = c.Put(u, b)
		}(url, body)

		// Reader (may hit or miss — both are valid; must not error)
		go func(u string) {
			defer wg.Done()
			_, _, err := c.Get(u)
			if err != nil {
				t.Errorf("Get(%q): unexpected error: %v", u, err)
			}
		}(url)
	}

	wg.Wait()
}

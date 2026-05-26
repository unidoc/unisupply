package scanner

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// defaultCacheTTL is how long a cached GitHub API response is considered fresh.
const defaultCacheTTL = 24 * time.Hour

// cacheEntry is the on-disk envelope written per cached URL. The body is
// stored gzip-compressed inside the JSON envelope to keep disk usage small.
type cacheEntry struct {
	// URL is stored for human readability and collision detection.
	URL string `json:"url"`
	// StatusCode is the HTTP status code of the cached response.
	StatusCode int `json:"status_code"`
	// ETag is the ETag header value from the response, if present.
	ETag string `json:"etag,omitempty"`
	// CachedAt is when the entry was written.
	CachedAt time.Time `json:"cached_at"`
	// GzipBody is the gzip-compressed response body.
	GzipBody []byte `json:"gzip_body"`
}

// maintainerCache is a disk-backed cache for GitHub API responses. It is safe
// for concurrent use from multiple goroutines within a single process, and
// atomic at the file level (write-then-rename) so multiple processes sharing
// the same directory cannot produce torn reads.
//
// On cache-directory creation failure the cache degrades gracefully: all Get
// calls return (nil, false, nil) and all Put calls are silent no-ops. The
// scanner continues without caching.
type maintainerCache struct {
	dir     string
	ttl     time.Duration
	nowFunc func() time.Time // injectable for tests; nil → time.Now

	// mu protects disabled only. File-level operations are lock-free because
	// the write-then-rename pattern guarantees atomic visibility.
	mu       sync.Mutex
	disabled bool
}

// newMaintainerCache returns a cache rooted at dir with the given TTL.
// If dir is empty, it falls back to os.UserCacheDir()+"/unisupply/maintainer".
// Cache-directory creation is attempted lazily on the first write, not here.
func newMaintainerCache(dir string, ttl time.Duration) *maintainerCache {
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			// os.UserCacheDir returning an error is rare (HOME not set, etc.).
			// Fall back to a temp-based path so the scan can still proceed.
			base = filepath.Join(os.TempDir(), "unisupply")
		}
		dir = filepath.Join(base, "unisupply", "maintainer")
	}
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	return &maintainerCache{dir: dir, ttl: ttl}
}

// now returns the current time, using the injectable nowFunc if set.
func (c *maintainerCache) now() time.Time {
	if c.nowFunc != nil {
		return c.nowFunc()
	}
	return time.Now()
}

// cacheKey returns the hex-encoded SHA-256 of the URL, used as the filename.
func cacheKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return fmt.Sprintf("%x", sum)
}

// cacheFilePath returns the full path to the file for the given URL.
func (c *maintainerCache) cacheFilePath(url string) string {
	return filepath.Join(c.dir, cacheKey(url)+".json.gz")
}

// ensureDir creates the cache directory on first use, disabling the cache if
// directory creation fails and logging a single warning.
func (c *maintainerCache) ensureDir() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disabled {
		return false
	}
	if err := os.MkdirAll(c.dir, 0o750); err != nil {
		log.Printf("maintainer cache: cannot create directory %q: %v — caching disabled for this scan", c.dir, err)
		c.disabled = true
		return false
	}
	return true
}

// isDisabled returns true when the cache is in degraded (no-op) mode.
func (c *maintainerCache) isDisabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disabled
}

// Get returns the cached body for url if a fresh entry exists (within TTL).
// Returns (body, true, nil) on hit, (nil, false, nil) on miss or expiry, and
// (nil, false, err) on an unexpected read error. The caller should treat
// (nil, false, nil) as a normal cache miss — proceed to fetch from the network.
func (c *maintainerCache) Get(url string) (body []byte, hit bool, err error) {
	if c.isDisabled() {
		return nil, false, nil
	}

	path := c.cacheFilePath(url)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil // normal miss
		}
		return nil, false, fmt.Errorf("maintainer cache: reading %s: %w", path, err)
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		// Corrupted entry: treat as miss; the next Put will overwrite it.
		return nil, false, nil
	}

	if c.now().Sub(entry.CachedAt) > c.ttl {
		return nil, false, nil // stale
	}

	body, err = gunzip(entry.GzipBody)
	if err != nil {
		return nil, false, fmt.Errorf("maintainer cache: decompressing entry for %s: %w", url, err)
	}
	return body, true, nil
}

// Put writes body to the cache under url. It uses a write-then-rename pattern
// so concurrent writers for the same key cannot produce torn reads: whichever
// rename wins is a complete, valid file. The loser's temp file is cleaned up.
// On cache-directory creation failure Put is a silent no-op (graceful degradation).
func (c *maintainerCache) Put(url string, body []byte) error {
	if !c.ensureDir() {
		return nil // graceful no-op
	}

	compressed, err := gzipBytes(body)
	if err != nil {
		return fmt.Errorf("maintainer cache: compressing body for %s: %w", url, err)
	}

	entry := cacheEntry{
		URL:        url,
		StatusCode: 200,
		CachedAt:   c.now(),
		GzipBody:   compressed,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("maintainer cache: marshaling entry for %s: %w", url, err)
	}

	// Write to a per-key temp file, then rename atomically.
	final := c.cacheFilePath(url)
	tmp := final + ".tmp." + fmt.Sprintf("%d", c.now().UnixNano())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("maintainer cache: writing temp file: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp) // best-effort cleanup
		return fmt.Errorf("maintainer cache: renaming cache file: %w", err)
	}
	return nil
}

// gzipBytes compresses src with gzip and returns the result.
func gzipBytes(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(src); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// gunzip decompresses src and returns the original bytes.
func gunzip(src []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

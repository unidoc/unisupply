package scanner

import (
	"fmt"
	"os"
	"testing"
)

// TestMain points the on-disk response caches at temporary directories, a new
// one for each scanner constructed. Tests serve fixtures from httptest servers
// whose ports are reused, within a run and across runs, so a shared cache (the
// developer's real one, or one for the whole run) could answer one test with
// another test's fixture. A test that exercises the cache across scanners
// sets diskCache itself.
func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "unisupply-scanner-test-cache-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "creating test cache dir:", err)
		os.Exit(1)
	}
	userCacheDir = func() (string, error) { return os.MkdirTemp(root, "") }
	code := m.Run()
	_ = os.RemoveAll(root)
	os.Exit(code)
}

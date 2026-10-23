package facts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/unidoc/unisupply/internal/version"
)

// HTTPStore is a read-only Store over gorisk's shared-facts API (GET {base}/api/v1/facts/...), so a scan outside gorisk reads
// what gorisk already knows instead of looking it all up again. The API key travels only in the Authorization header.
//
// A miss (404) is (nil, false, nil). Any other failure (a bad key, a rate limit that outlasts the wait, a network error, an
// answer that is not the JSON of the fact) is a miss with the error returned: unisupply treats that as a miss and goes on, so
// the facts service can be down without failing a scan. Put* do nothing: a customer's scan never writes to the shared
// facts, which also keeps private module names out of them.
type HTTPStore struct {
	base   string
	key    string
	client *http.Client
	// maxRetryWait is the longest Retry-After honoured, once; longer is a miss.
	maxRetryWait time.Duration

	mu       sync.Mutex
	cache    map[string]cached
	disabled error // set by a 401 or 403: the key is no good, so no further request is made
}

type cached struct {
	body []byte // nil: a miss
	err  error
}

var _ Store = (*HTTPStore)(nil)

// NewHTTPStore returns a store for the API at base ("https://gorisk.dev"). HTTPS is required unless the host is loopback
// (for tests and a local server). The key must not be empty.
func NewHTTPStore(base, key string) (*HTTPStore, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("facts URL %q is not an http(s) URL", base)
	}
	if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("facts URL %q: https is required (plain http is allowed for loopback hosts only)", base)
	}
	if u.RawQuery != "" || u.User != nil {
		return nil, errors.New("facts URL must not carry a query or credentials")
	}
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("facts API key is empty")
	}
	return &HTTPStore{
		base: u.String(), key: strings.TrimSpace(key), maxRetryWait: 5 * time.Second, cache: map[string]cached{},
		client: &http.Client{
			Timeout: 10 * time.Second,
			// a redirect would carry the key to another host
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// get returns the body of a hit, nil for a miss.
func (s *HTTPStore) get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	target := s.base + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	s.mu.Lock()
	if c, ok := s.cache[target]; ok {
		s.mu.Unlock()
		return c.body, c.err
	}
	if s.disabled != nil {
		err := s.disabled
		s.mu.Unlock()
		return nil, err
	}
	s.mu.Unlock()

	body, err := s.fetch(ctx, target, true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() == nil { // a cancelled scan says nothing about the fact
		s.cache[target] = cached{body, err}
	}
	return body, err
}

func (s *HTTPStore) fetch(ctx context.Context, target string, mayRetry bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return nil, errors.New("facts request could not be built")
	}
	req.Header.Set("Authorization", "Bearer "+s.key)
	req.Header.Set("User-Agent", "unisupply/"+version.Version)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		// the error text of net/http carries the URL, never the header; the URL has no key
		return nil, fmt.Errorf("facts API: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("facts API: %w", err)
		}
		return b, nil
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		err := fmt.Errorf("facts API: HTTP %d (the API key was refused or lacks the scope); no further facts are requested", resp.StatusCode)
		s.mu.Lock()
		s.disabled = err
		s.mu.Unlock()
		return nil, err
	case resp.StatusCode == http.StatusTooManyRequests:
		wait, ok := retryAfter(resp.Header.Get("Retry-After"))
		if !mayRetry || !ok || wait > s.maxRetryWait {
			return nil, errors.New("facts API: rate limited (HTTP 429)")
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return s.fetch(ctx, target, false)
	}
	return nil, fmt.Errorf("facts API: HTTP %d", resp.StatusCode)
}

// retryAfter reads the delay-seconds form of Retry-After.
func retryAfter(h string) (time.Duration, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || n < 0 {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

func decode[T any](body []byte, what string) (*T, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, false, fmt.Errorf("facts API: the %s answer is not valid JSON", what)
	}
	return &v, true, nil
}

func (s *HTTPStore) GetModule(ctx context.Context, path, version string) (*Module, bool, error) {
	b, err := s.get(ctx, "/api/v1/facts/modules", url.Values{"path": {path}, "version": {version}})
	if err != nil {
		return nil, false, err
	}
	return decode[Module](b, "module")
}

func (s *HTTPStore) GetAdvisory(ctx context.Context, id string) (*Advisory, bool, error) {
	b, err := s.get(ctx, "/api/v1/facts/advisories/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, false, err
	}
	return decode[Advisory](b, "advisory")
}

func (s *HTTPStore) GetFix(ctx context.Context, module, version string) (*Fix, bool, error) {
	b, err := s.get(ctx, "/api/v1/facts/fixes", url.Values{"module": {module}, "version": {version}})
	if err != nil {
		return nil, false, err
	}
	return decode[Fix](b, "fix")
}

// Put* are no-ops: the shared facts are the server's to write.
func (s *HTTPStore) PutModule(context.Context, *Module) error     { return nil }
func (s *HTTPStore) PutAdvisory(context.Context, *Advisory) error { return nil }
func (s *HTTPStore) PutFix(context.Context, *Fix) error           { return nil }

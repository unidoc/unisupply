package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const noTagsPseudo = "v0.0.0-20251001235044-fca9a0999f15"

// noTagsProxy serves a module that has no tagged release: @latest answers
// latestStatus (the live proxy answers 404), the pinned pseudo-version answers
// .info and .mod.
func noTagsProxy(t *testing.T, latestStatus int, infoStatus int, gomod string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/github.com/itchyny/go-yaml/@latest":
			w.WriteHeader(latestStatus)
		case r.URL.Path == "/github.com/itchyny/go-yaml/@v/"+noTagsPseudo+".info":
			if infoStatus != http.StatusOK {
				w.WriteHeader(infoStatus)
				return
			}
			fmt.Fprintf(w, `{"Version":%q,"Time":"2025-10-01T23:50:44Z","Origin":{"VCS":"git","URL":"https://github.com/itchyny/go-yaml"}}`, noTagsPseudo)
		case r.URL.Path == "/github.com/itchyny/go-yaml/@v/"+noTagsPseudo+".mod":
			fmt.Fprint(w, gomod)
		case r.URL.Path == "/github.com/itchyny/go-yaml/@v/list":
			// empty list, as the live proxy answers
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func checkNoTags(t *testing.T, srv *httptest.Server) (*MaintenanceInfo, error) {
	t.Helper()
	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = srv.URL
	ms.diskCache = nil
	return ms.checkModule(context.Background(), "github.com/itchyny/go-yaml", noTagsPseudo)
}

// A dependency with no tagged release (@latest 404/410) is measured from its
// pinned version: before the fix ModCheckFailed was set on every run.
func TestMaintenanceScanner_NoTaggedRelease(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusGone} {
		srv := noTagsProxy(t, status, http.StatusOK, "module github.com/itchyny/go-yaml\n\ngo 1.18\n")
		info, err := checkNoTags(t, srv)
		if err != nil {
			t.Fatalf("@latest %d: %v", status, err)
		}
		if info.ModCheckFailed {
			t.Errorf("@latest %d: ModCheckFailed set for a module with no tags", status)
		}
		if info.LatestVersion != noTagsPseudo {
			t.Errorf("@latest %d: LatestVersion = %q, want the pinned %q", status, info.LatestVersion, noTagsPseudo)
		}
		if want := time.Date(2025, 10, 1, 23, 50, 44, 0, time.UTC); !info.LastRelease.Equal(want) {
			t.Errorf("@latest %d: LastRelease = %v, want %v", status, info.LastRelease, want)
		}
		if info.Deprecated || info.Retracted {
			t.Errorf("@latest %d: Deprecated=%v Retracted=%v on a clean go.mod", status, info.Deprecated, info.Retracted)
		}
	}
}

// Deprecation and retraction are read from the pinned version's go.mod.
func TestMaintenanceScanner_NoTaggedRelease_ReadsPinnedGoMod(t *testing.T) {
	const gomod = "// Deprecated: use another.\nmodule github.com/itchyny/go-yaml\n\nretract " + noTagsPseudo + " // bad\n"
	info, err := checkNoTags(t, noTagsProxy(t, http.StatusNotFound, http.StatusOK, gomod))
	if err != nil {
		t.Fatal(err)
	}
	if info.ModCheckFailed || !info.Deprecated || info.DeprecationMessage != "use another." {
		t.Errorf("deprecation not read from the pinned go.mod: %+v", info)
	}
	if !info.Retracted {
		t.Errorf("retraction not read from the pinned go.mod: %+v", info)
	}
}

// Negative controls: a real failure stays a failure.
func TestMaintenanceScanner_NoTaggedRelease_RealFailuresStayFailures(t *testing.T) {
	// @latest 5xx: not "no tags", so the module stays unchecked.
	info, err := checkNoTags(t, noTagsProxy(t, http.StatusInternalServerError, http.StatusOK, "module github.com/itchyny/go-yaml\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModCheckFailed {
		t.Error("@latest 500 must leave ModCheckFailed set")
	}
	if info.LatestVersion != "" {
		t.Errorf("@latest 500: LatestVersion = %q, want empty", info.LatestVersion)
	}

	// @latest 404 and the pinned .info failing: no data at all, an error.
	if _, err := checkNoTags(t, noTagsProxy(t, http.StatusNotFound, http.StatusInternalServerError, "")); err == nil {
		t.Error("@latest 404 with a failing pinned .info must be an error")
	}
}

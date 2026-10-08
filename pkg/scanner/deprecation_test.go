package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// protobufGoMod is the head of github.com/golang/protobuf@v1.5.4's go.mod as
// served by proxy.golang.org.
const protobufGoMod = `// Deprecated: Use the "google.golang.org/protobuf" module instead.
module github.com/golang/protobuf

go 1.17

require (
	github.com/google/go-cmp v0.5.5
	google.golang.org/protobuf v1.33.0
)
`

func TestGoModDeprecation(t *testing.T) {
	tests := []struct {
		name  string
		gomod string
		want  string
	}{
		{"recorded golang/protobuf", protobufGoMod, `Use the "google.golang.org/protobuf" module instead.`},
		{"not deprecated", "module example.com/ok\n\ngo 1.21\n", ""},
		{
			"comment on the module line",
			"module example.com/old // Deprecated: use example.com/new\n\ngo 1.21\n",
			"use example.com/new",
		},
		{
			"comment not on the module directive",
			"module example.com/ok\n\ngo 1.21\n\n// Deprecated: this is about the require below\nrequire example.com/dep v1.0.0\n",
			"",
		},
		{
			"Deprecated not at the start of a paragraph",
			"// This module is not Deprecated: really.\nmodule example.com/ok\n",
			"",
		},
		{"unparsable go.mod", "this is not a go.mod\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := goModDeprecation([]byte(tt.gomod)); got != tt.want {
				t.Errorf("goModDeprecation = %q, want %q", got, tt.want)
			}
		})
	}
}

// checkModule reads the deprecation notice from the latest version's go.mod,
// not the scanned version's, and keeps the message.
func TestMaintenanceScanner_GoModDeprecation(t *testing.T) {
	const mod = "github.com/golang/protobuf"
	var requested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		switch r.URL.Path {
		case "/github.com/golang/protobuf/@v/v1.4.0.info":
			fmt.Fprint(w, `{"Version":"v1.4.0","Time":"2020-04-01T00:00:00Z"}`)
		case "/github.com/golang/protobuf/@latest":
			fmt.Fprint(w, `{"Version":"v1.5.4","Time":"2024-03-06T00:00:00Z"}`)
		case "/github.com/golang/protobuf/@v/list":
			fmt.Fprint(w, "v1.4.0\nv1.5.4\n")
		case "/github.com/golang/protobuf/@v/v1.5.4.mod":
			fmt.Fprint(w, protobufGoMod)
		case "/github.com/golang/protobuf/@v/v1.4.0.mod":
			fmt.Fprint(w, "module github.com/golang/protobuf\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = srv.URL
	info, err := ms.checkModule(context.Background(), mod, "v1.4.0")
	if err != nil {
		t.Fatalf("checkModule: %v", err)
	}
	if !info.Deprecated || info.DeprecationMessage != `Use the "google.golang.org/protobuf" module instead.` {
		t.Errorf("Deprecated = %v, message %q, want the v1.5.4 notice", info.Deprecated, info.DeprecationMessage)
	}
	for _, p := range requested {
		if p == "/github.com/golang/protobuf/@v/v1.4.0.mod" {
			t.Error("the scanned version's go.mod was read; deprecation comes from the latest version")
		}
	}
}

// A failed go.mod fetch reports no deprecation rather than failing the module.
func TestMaintenanceScanner_GoModFetchFailureIsNotDeprecation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example.com/m/@latest":
			fmt.Fprint(w, `{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`)
		case "/example.com/m/@v/v1.0.0.info":
			fmt.Fprint(w, `{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`)
		case "/example.com/m/@v/v1.0.0.mod":
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = srv.URL
	info, err := ms.checkModule(context.Background(), "example.com/m", "v1.0.0")
	if err != nil {
		t.Fatalf("checkModule: %v", err)
	}
	if info.Deprecated || info.DeprecationMessage != "" {
		t.Errorf("Deprecated = %v (%q), want false on a failed go.mod fetch", info.Deprecated, info.DeprecationMessage)
	}
}

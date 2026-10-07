package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

func vanityScore(mi *scanner.MaintainerInfo) *scorer.DependencyScore {
	return &scorer.DependencyScore{
		Module: "gopkg.in/yaml.v3", Version: "v3.0.1", Direct: true,
		RiskScore: 60, RiskLevel: scorer.RiskHigh, MaintainerInfo: mi,
	}
}

func TestWriteDependencyDetail_SourceRepo(t *testing.T) {
	noColor := func(_, s string) string { return s }

	t.Run("shown for a mapped module", func(t *testing.T) {
		ds := vanityScore(&scanner.MaintainerInfo{
			DataAvailable: true, Owner: "go-yaml", Repo: "yaml",
			SourceRepo: "github.com/go-yaml/yaml", SourceRepoVia: scanner.SourceViaGopkgIn,
		})
		var buf bytes.Buffer
		writeDependencyDetail(&buf, ds, noColor, true)
		if want := "Source repository: github.com/go-yaml/yaml (via gopkg_in_rule)"; !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q:\n%s", want, buf.String())
		}
	})

	t.Run("absent for a github.com module", func(t *testing.T) {
		ds := vanityScore(&scanner.MaintainerInfo{DataAvailable: true, Owner: "spf13", Repo: "cobra"})
		var buf bytes.Buffer
		writeDependencyDetail(&buf, ds, noColor, true)
		if strings.Contains(buf.String(), "Source repository") {
			t.Errorf("unexpected source line:\n%s", buf.String())
		}
	})
}

func TestWriteJSON_MaintainerSourceRepo(t *testing.T) {
	graph := testutil.MakeGraph(testutil.DepSpec{Path: "gopkg.in/yaml.v3", Version: "v3.0.1", Direct: true})

	maintainerOf := func(t *testing.T, mi *scanner.MaintainerInfo) map[string]any {
		t.Helper()
		ps := &scorer.ProjectScore{
			OverallScore: 60, OverallLevel: scorer.RiskHigh,
			Dependencies: []*scorer.DependencyScore{vanityScore(mi)}, HighRiskCount: 1,
		}
		var buf bytes.Buffer
		if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
			t.Fatalf("WriteJSON() failed: %v", err)
		}
		var raw struct {
			Dependencies []struct {
				Maintainer map[string]any `json:"maintainer"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(raw.Dependencies) != 1 || raw.Dependencies[0].Maintainer == nil {
			t.Fatalf("maintainer object missing: %s", buf.String())
		}
		return raw.Dependencies[0].Maintainer
	}

	t.Run("exposed", func(t *testing.T) {
		m := maintainerOf(t, &scanner.MaintainerInfo{
			DataAvailable: true, SourceRepo: "github.com/go-yaml/yaml", SourceRepoVia: scanner.SourceViaGopkgIn,
		})
		if m["source_repo"] != "github.com/go-yaml/yaml" || m["source_repo_via"] != "gopkg_in_rule" {
			t.Errorf("source_repo/source_repo_via = %v / %v", m["source_repo"], m["source_repo_via"])
		}
	})

	t.Run("kept when GitHub data is unavailable", func(t *testing.T) {
		m := maintainerOf(t, &scanner.MaintainerInfo{
			UnavailableReason: "github_api_error",
			SourceRepo:        "github.com/go-yaml/yaml", SourceRepoVia: scanner.SourceViaGopkgIn,
		})
		if m["source_repo"] != "github.com/go-yaml/yaml" {
			t.Errorf("source_repo = %v, want it kept", m["source_repo"])
		}
	})

	t.Run("omitted for a github.com module", func(t *testing.T) {
		m := maintainerOf(t, &scanner.MaintainerInfo{DataAvailable: true})
		for _, key := range []string{"source_repo", "source_repo_via"} {
			if _, ok := m[key]; ok {
				t.Errorf("%s present, want omitted", key)
			}
		}
	})
}

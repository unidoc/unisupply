package runner

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/unidoc/unisupply/pkg/facts"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// factReader is the facts store as grading uses it: reads through it with the freshness of the grade's date, and writes
// back what a lookup found. A nil store makes every method a no-op, so a caller without one runs the lookups as before.
type factReader struct {
	store    facts.Store
	policy   facts.Policy
	date     time.Time
	analysed time.Time
}

func (fr *factReader) active() bool { return fr != nil && fr.store != nil }

func (fr *factReader) pol() facts.Policy {
	if fr.policy == (facts.Policy{}) {
		return facts.DefaultPolicy
	}
	return fr.policy
}

// module is the fresh status of a module version, aged to the grade's date.
func (fr *factReader) module(ctx context.Context, path, version string) (*scanner.MaintenanceInfo, bool) {
	if !fr.active() {
		return nil, false
	}
	m, ok, err := fr.store.GetModule(ctx, path, version)
	if err != nil || !ok || !facts.Fresh(m.FetchedAt, fr.date, fr.pol().Module) {
		return nil, false
	}
	info := m.Info
	info.AgeAt(fr.date)
	return &info, true
}

// putModule stores a module's status when it is a whole answer: every notice and the archived flag were read (or the
// repository is known to be unreadable for good). A status with a lookup that failed is looked up again next time.
func (fr *factReader) putModule(ctx context.Context, path, version string, info *scanner.MaintenanceInfo) {
	if !fr.active() || info == nil || info.ModCheckFailed {
		return
	}
	if info.ArchivedCheck != scanner.ArchivedChecked && info.ArchivedCheck != scanner.ArchivedUnsupported && !info.RepositoryNotFound {
		return
	}
	src := "module_proxy"
	if info.ArchivedCheck == scanner.ArchivedChecked {
		src = "module_proxy+github"
	}
	_ = fr.store.PutModule(ctx, &facts.Module{Path: path, Version: version, Info: *info, FetchedAt: fr.date, Source: src})
}

// splitModules separates the graph into the modules that need a lookup and the fresh statuses of the others. Without a store
// it returns the graph itself and nothing cached.
func (fr *factReader) splitModules(ctx context.Context, g *resolver.Graph) (*resolver.Graph, map[string]*scanner.MaintenanceInfo) {
	if !fr.active() {
		return g, nil
	}
	cached := map[string]*scanner.MaintenanceInfo{}
	need := map[string]bool{}
	for path, d := range g.Dependencies {
		if info, ok := fr.module(ctx, path, d.Module.Version); ok {
			cached[path] = info
		} else {
			need[path] = true
		}
	}
	if len(cached) == 0 {
		return g, nil
	}
	return subgraph(g, need), cached
}

// storeModules writes back the statuses the scanners just read.
func (fr *factReader) storeModules(ctx context.Context, g *resolver.Graph, maintenance map[string]*scanner.MaintenanceInfo) {
	if !fr.active() {
		return
	}
	for path, info := range maintenance {
		if d := g.Dependencies[path]; d != nil {
			fr.putModule(ctx, path, d.Module.Version, info)
		}
	}
}

// knownSeverity is the severity when somebody published one, else "".
func knownSeverity(s string) string {
	switch u := strings.ToUpper(strings.TrimSpace(s)); u {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return u
	}
	return ""
}

// applyAdvisories replaces the severity and the known-exploited status of the findings with those of a fact that is fresh and
// newer than the analysis: the analysis keeps what it learned when it was made, and the store what was learned since.
func (fr *factReader) applyAdvisories(ctx context.Context, vulns map[string][]scanner.Vulnerability) {
	if !fr.active() {
		return
	}
	for _, list := range vulns {
		for i := range list {
			v := &list[i]
			a, ok, err := fr.store.GetAdvisory(ctx, v.ID)
			if err != nil || !ok || !facts.Fresh(a.FetchedAt, fr.date, fr.pol().Advisory) || !a.FetchedAt.After(fr.analysed) {
				continue
			}
			if sev := knownSeverity(a.Severity); sev != "" {
				v.Severity, v.SeveritySource = sev, a.SeveritySource
				v.EnrichmentFailed, v.EnrichmentErrors = false, nil
			}
			if a.KEVChecked {
				v.KEVChecked, v.InKEV, v.KEVDateAdded = true, a.InKEV, a.KEVDateAdded
			}
		}
	}
}

// storeAdvisories writes what the analysis knows of each advisory, as of the time it was made, unless the store already has
// something newer.
func (fr *factReader) storeAdvisories(ctx context.Context, vulns map[string][]scanner.Vulnerability) {
	if !fr.active() {
		return
	}
	seen := map[string]bool{}
	for _, list := range vulns {
		for i := range list {
			v := &list[i]
			if seen[v.ID] {
				continue
			}
			seen[v.ID] = true
			adv := &facts.Advisory{
				ID: v.ID, Aliases: v.Aliases, Severity: knownSeverity(v.Severity), SeveritySource: v.SeveritySource,
				PublishedAt: v.PublishedAt, KEVChecked: v.KEVChecked, InKEV: v.InKEV, KEVDateAdded: v.KEVDateAdded,
				FetchedAt: fr.analysed,
			}
			if old, ok, err := fr.store.GetAdvisory(ctx, v.ID); err == nil && ok {
				if !old.FetchedAt.Before(fr.analysed) {
					continue
				}
				// what the analysis could not learn (no severity published, no catalog check) is not forgotten
				if adv.Severity == "" {
					adv.Severity, adv.SeveritySource = knownSeverity(old.Severity), old.SeveritySource
				}
				if !adv.KEVChecked && old.KEVChecked {
					adv.KEVChecked, adv.InKEV, adv.KEVDateAdded = true, old.InKEV, old.KEVDateAdded
				}
			}
			_ = fr.store.PutAdvisory(ctx, adv)
		}
	}
}

// resolveFixes sets the fix release dates of the findings. Without a store it is resolveAllFixDates. With one, a finding
// whose fix is in the store gets it from there, and the proxy is asked only for the others, whose answers are stored.
func resolveFixes(ctx context.Context, fr *factReader, opts scanner.FixDateOptions, vulns map[string][]scanner.Vulnerability) {
	if !fr.active() {
		resolveAllFixDates(ctx, opts, fixDateStageTimeout, vulns)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, fixDateStageTimeout)
	defer cancel()
	paths := make([]string, 0, len(vulns))
	for path := range vulns {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		list := vulns[path]
		var todo []int
		for i := range list {
			v := &list[i]
			v.FixReleasedAt, v.FixDateSource = nil, ""
			if v.FixedVersion == "" {
				continue
			}
			if fx, ok, err := fr.store.GetFix(ctx, path, v.FixedVersion); err == nil && ok && facts.Fresh(fx.FetchedAt, fr.date, fr.pol().Fix) {
				t := fx.ReleasedAt
				v.FixReleasedAt, v.FixDateSource, v.FixRequiresGo = &t, fx.Source, fx.RequiresGo
				v.DaysUnpatched = daysBetween(fr.date, t)
				continue
			}
			todo = append(todo, i)
		}
		if len(todo) == 0 {
			continue
		}
		sub := make([]scanner.Vulnerability, len(todo))
		for j, i := range todo {
			sub[j] = list[i]
		}
		if path == stdlibModule {
			scanner.ResolveStdlibFixDates(ctx, opts, sub)
		} else {
			scanner.ResolveFixDates(ctx, opts, path, sub)
			// the Go release each fix needs, so the report can say when taking it raises the module's minimum Go
			scanner.ResolveFixGoRequirements(ctx, opts, path, sub)
		}
		for j, i := range todo {
			list[i] = sub[j]
			v := &sub[j]
			// a fix with no date, or whose go.mod could not be read, is asked for again next time
			if v.FixReleasedAt == nil || v.FixDateSource == "" || (v.FixRequiresGo == "" && path != stdlibModule) {
				continue
			}
			_ = fr.store.PutFix(ctx, &facts.Fix{Module: path, Version: v.FixedVersion, ReleasedAt: *v.FixReleasedAt, Source: v.FixDateSource, RequiresGo: v.FixRequiresGo, FetchedAt: fr.date})
		}
	}
}

func daysBetween(now, t time.Time) int {
	days := int(now.Sub(t).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

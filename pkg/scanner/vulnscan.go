package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"runtime/debug"
	"slices"
	"strings"

	"golang.org/x/vuln/scan"

	"github.com/unidoc/unisupply/pkg/offline"
)

// CalledPassMode says when govulncheck's called pass (symbol level: which vulnerable functions the code reaches) runs.
// The imported pass (package level: which vulnerable packages the code imports) always runs first and is much lighter, so
// the called pass is only worth its time and memory when it can change the answer.
type CalledPassMode string

const (
	// CalledPassAuto runs the imported pass first and the called pass only when VulnScanOptions.NeedsCalledPass says it can
	// change the grade. Without that predicate it behaves as CalledPassAlways. It is the default.
	CalledPassAuto CalledPassMode = "auto"
	// CalledPassAlways runs the called pass alone, as every release before the imported pass existed.
	CalledPassAlways CalledPassMode = "always"
	// CalledPassNever runs the imported pass alone. Findings are never "called", so a grade built on it is only a floor:
	// use it to get a quick, cheap listing, not to publish a letter.
	CalledPassNever CalledPassMode = "never"
)

// ParseCalledPassMode reads a flag value; the empty string is CalledPassAuto.
func ParseCalledPassMode(s string) (CalledPassMode, error) {
	switch m := CalledPassMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return CalledPassAuto, nil
	case CalledPassAuto, CalledPassAlways, CalledPassNever:
		return m, nil
	}
	return "", fmt.Errorf("unknown called-pass mode %q (want auto, always or never)", s)
}

// Values of ScanInfo.CalledPass.
const (
	CalledPassRan     = "ran"     // the called pass ran: findings carry their called/imported verdict
	CalledPassSkipped = "skipped" // only the imported pass ran; ScanInfo.CalledPassReason says why
)

// NeedsCalledPassFunc decides, from the findings of the imported pass (severities and known-exploited status already
// filled in), whether the called pass could change the grade, and says why in one sentence for the report. The grading
// code provides it (grade.CalledPassCanChangeLetter), so it follows the grading rules.
type NeedsCalledPassFunc func(imported map[string][]Vulnerability) (needed bool, reason string)

// VulnScanOptions carries the credentials ScanVulnsWithOptions forwards to the
// severity enrichment lookups.
type VulnScanOptions struct {
	// GitHubToken is sent as a Bearer token to api.github.com only.
	GitHubToken string
	// NVDAPIKey is sent as the apiKey header to services.nvd.nist.gov only.
	NVDAPIKey string
	// Info, when non-nil, is filled with the platform, govulncheck and
	// vulnerability-database versions the scan ran with. Platform is set as
	// soon as a scan starts; the rest come from govulncheck's config message
	// and stay empty when the output has none.
	Info *ScanInfo

	// CalledPass is when the called pass runs; the zero value is CalledPassAuto.
	CalledPass CalledPassMode
	// NeedsCalledPass is the "could this change the letter?" test for CalledPassAuto. Nil means every scan needs the
	// called pass, so a caller that does not grade gets the old behaviour.
	NeedsCalledPass NeedsCalledPassFunc
}

// govulncheck's -scan levels: the imported pass and the called pass.
const (
	scanLevelPackage = "package"
	scanLevelSymbol  = "symbol"
)

// ScanVulnsWithOptions is ScanVulns with explicit credentials for the
// enrichment lookups. It returns the same values as ScanVulns.
//
// In CalledPassAuto mode govulncheck runs at package level first; when the findings (once their severities and
// known-exploited status are known) cannot change the grade by being called, that is the result: findings are
// "imported" and ScanInfo.CalledPass says "skipped" with the reason. Otherwise it runs again at symbol level and that
// result replaces the first. The loaded packages and call graph of each pass are released before the next network step.
func ScanVulnsWithOptions(ctx context.Context, projectDir string, opts VulnScanOptions) (vulns map[string][]Vulnerability, warnings []string, scanned bool, err error) {
	if offline.Enabled() {
		// govulncheck runs in-process and reaches vuln.go.dev through
		// http.DefaultClient, so offline mode would refuse its requests and
		// leave a transport error dressed up as a scan failure. Skip it
		// outright and say why: an empty vulnerability set with no explanation
		// reads as "no vulnerabilities found", which is the one wrong answer.
		return nil, []string{"offline — vulnerability scan skipped (no local vuln DB mirror configured)"}, false, nil
	}

	// govulncheck's -C only moves package loading; it resolves the Go version
	// and GOROOT for the standard library in this process's working directory.
	// Resolve the project's own so the result does not depend on where
	// unisupply was launched from.
	projectEnv, projectErr := resolveGoEnv(ctx, projectDir)
	if projectErr != nil {
		warnings = append(warnings, fmt.Sprintf("could not resolve the project's Go toolchain (%v); standard-library vulnerabilities are checked against the Go version of unisupply's working directory", projectErr))
	}
	// govulncheck runs in this process, compiled with unisupply's own Go: code that needs a newer one cannot be loaded.
	if projectErr == nil {
		if err := CheckToolchain(projectEnv.version); err != nil {
			return nil, nil, false, &ScanError{Kind: FailPermanent, Reason: ReasonNeedsNewerGo, Err: err}
		}
	}
	// A failure here only costs stdlib file positions, so it is not reported.
	scannerEnv, scannerErr := resolveGoEnv(ctx, "")
	parseOpts := gvcParseOptions{}
	if projectErr == nil && scannerErr == nil {
		parseOpts = gvcParseOptions{scannerGOROOT: scannerEnv.root, projectGOROOT: projectEnv.root}
	}
	if opts.Info != nil {
		*opts.Info = ScanInfo{Platform: scanPlatform(), GovulncheckVersion: govulncheckVersion(readBuildInfo)}
		parseOpts.info = opts.Info
	}

	run := &govulncheckRun{
		projectDir: projectDir, env: govulncheckEnv(os.Environ(), projectEnv.version),
		parseOpts: parseOpts, projectEnv: projectEnv, projectErr: projectErr, scannerEnv: scannerEnv, scannerErr: scannerErr, opts: opts,
	}
	mode := opts.CalledPass
	if mode == "" {
		mode = CalledPassAuto
	}
	note := func(state, reason string) {
		if opts.Info != nil {
			opts.Info.CalledPassMode, opts.Info.CalledPass, opts.Info.CalledPassReason = string(mode), state, reason
		}
	}
	if mode == CalledPassAlways || (mode == CalledPassAuto && opts.NeedsCalledPass == nil) {
		reason := "called-pass is always"
		if mode == CalledPassAuto {
			reason = "no test for whether the called pass could change the grade was given"
		}
		vulns, warnings, scanned, err = run.pass(ctx, scanLevelSymbol, warnings)
		if scanned {
			note(CalledPassRan, reason)
		}
		return vulns, warnings, scanned, err
	}

	start := slices.Clone(warnings)
	vulns, warnings, scanned, err = run.pass(ctx, scanLevelPackage, warnings)
	if err != nil || !scanned {
		return vulns, warnings, scanned, err
	}
	reason := "the called pass is turned off (called-pass never)"
	if mode == CalledPassAuto {
		var needed bool
		needed, reason = opts.NeedsCalledPass(vulns)
		if needed {
			// The imported result was only the first look: the called one replaces it, warnings included (it reports
			// the same severity and threat-intel lookups again). A called pass that fails is a failed scan, never a
			// finished one that happens to list imported findings.
			vulns, warnings, scanned, err = run.pass(ctx, scanLevelSymbol, start)
			if scanned {
				note(CalledPassRan, reason)
			}
			return vulns, warnings, scanned, err
		}
	}
	note(CalledPassSkipped, reason)
	return vulns, warnings, scanned, err
}

// govulncheckRun is what the passes of one scan share.
type govulncheckRun struct {
	projectDir string
	env        []string
	parseOpts  gvcParseOptions
	projectEnv goEnv
	projectErr error
	scannerEnv goEnv
	scannerErr error
	opts       VulnScanOptions
}

// pass runs govulncheck once at the given scan level, then enriches the findings. warnings are those so far.
func (r *govulncheckRun) pass(ctx context.Context, level string, warnings []string) (map[string][]Vulnerability, []string, bool, error) {
	var stdout, stderrBuf bytes.Buffer

	// govulncheck exits non-zero when vulns are found (JSON mode returns nil in that
	// case via jsonHandler.Flush), so exitErr != nil only signals a real scan failure.
	// scan.Command runs govulncheck in-process; errors come back through Wait() as Go
	// error values, not written to stderr. Prefer stderrBuf when populated (future-proof),
	// fall back to exitErr.Error() for the common in-process case.
	exitErr := runGovulncheck(ctx, r.env, r.projectDir, level, &stdout, &stderrBuf)
	// The packages and the call graph govulncheck loaded are garbage now; the stages that follow wait on the network
	// (severity and threat-intel lookups), and without this the process would keep several GB until the runtime
	// returns them, which can take minutes. Nothing here holds them: cmd keeps only the output buffers.
	releaseMemory()

	// scanErr is the typed failure the caller gets next to the warnings; nil while the scan is sound.
	var scanErr *ScanError
	if exitErr != nil {
		// scan.Command runs govulncheck in-process; errors surface via Wait(), not stderr.
		// The library already prefixes errors with "govulncheck:" (derrors.Wrap).
		// Prefer stderrBuf when populated (future subprocess mode), but don't double-prefix.
		msg := strings.TrimSpace(stderrBuf.String())
		if msg == "" {
			msg = exitErr.Error()
		} else if !strings.HasPrefix(msg, "govulncheck:") {
			msg = "govulncheck: " + msg
		}
		if terr := toolchainErrorFrom(msg); terr != nil {
			msg = terr.Error()
		}
		// The warning and the reason are published: neither carries the path of the project or of the module cache on this
		// machine. The project's go env gives the cache; when it failed (the project needs a newer Go), the scanner's does.
		modCache := r.projectEnv.modCache
		if r.projectErr != nil && r.scannerErr == nil {
			modCache = r.scannerEnv.modCache
		}
		// The excluded package's directory is read before the cut, which takes the module cache out of it.
		excluded := excludedDir(msg)
		msg = trimPaths(msg, r.projectDir, modCache)
		warnings = append(warnings, msg)
		scanErr = classifyScanFailure(msg, ctx.Err())
		// "no packages matched" is also what a module whose files all need cgo gives when cgo is off: say so, but only
		// when the go command confirms cgo is off and a file of the module imports "C".
		if scanErr.Reason == ReasonNoPackages && r.projectErr == nil && r.projectEnv.cgo == "0" && hasCgoImport(r.projectDir) {
			scanErr.Reason = ReasonCgoOnly
		}
		// Likewise an imported package that the build leaves out, a dependency or one of the project's own, is
		// cgo_dependency when cgo is off and its files import "C".
		if scanErr.Reason == ReasonBuildConstraints && r.projectErr == nil && r.projectEnv.cgo == "0" && dirImportsC(excluded) {
			scanErr.Reason = ReasonCgoDependency
		}
	}

	if stdout.Len() == 0 {
		warnings = append(warnings, "govulncheck produced no output")
		if scanErr == nil {
			scanErr = &ScanError{Kind: FailPermanent, Reason: ReasonUnknown, Err: errors.New("govulncheck produced no output")}
		}
		return nil, warnings, false, scanErr
	}

	results, err := parseGovulncheckJSONWithOptions(&stdout, r.parseOpts)
	// the raw output is parsed into results; do not keep both through the lookups below
	stdout = bytes.Buffer{}
	if err != nil {
		if scanErr == nil {
			scanErr = &ScanError{Kind: FailPermanent, Reason: ReasonUnknown, Err: err}
		}
		return nil, append(warnings, err.Error()), false, scanErr
	}

	// Enrich UNKNOWN-severity vulnerabilities via OSV + GHSA.
	enricher := NewVulnEnricher(VulnEnricherOptions{GitHubToken: r.opts.GitHubToken, NVDAPIKey: r.opts.NVDAPIKey})
	var enrichWarnings []string
	// Sorted module order keeps the warning order, and the single-failure path
	// in collapseSeverityLookupWarnings, stable across runs.
	for _, modPath := range slices.Sorted(maps.Keys(results)) {
		modVulns := results[modPath]
		for i := range modVulns {
			if modVulns[i].Severity != "UNKNOWN" && modVulns[i].Severity != "" {
				continue
			}
			enrichWarnings = append(enrichWarnings, enricher.Enrich(ctx, &modVulns[i])...)
		}
		results[modPath] = modVulns
	}
	warnings = append(warnings, collapseSeverityLookupWarnings(enrichWarnings)...)

	tiWarnings, kevStale := enrichThreatIntelStale(ctx, NewThreatIntelClient(ThreatIntelOptions{}), results)
	warnings = append(warnings, tiWarnings...)
	if r.opts.Info != nil && !kevStale.IsZero() {
		r.opts.Info.KEVStaleSince = &kevStale
	}

	// A non-nil exitErr means govulncheck failed even though it emitted parseable
	// output, so the results are partial. Report the axis as unmeasured rather
	// than scoring an incomplete scan as a complete one.
	if scanErr != nil {
		return results, warnings, false, scanErr
	}
	return results, warnings, true, nil
}

// releaseMemory hands the heap govulncheck used back to the operating system now. It is a variable so tests can count calls.
// runGovulncheck runs govulncheck in this process at the given scan level and returns its error. It is a variable so tests can
// answer with recorded output instead of loading packages and reading the vulnerability database.
var runGovulncheck = func(ctx context.Context, env []string, dir, level string, stdout, stderr io.Writer) error {
	cmd := scan.Command(ctx, "-json", "-scan", level, "-C", dir, "./...")
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting govulncheck: %w", err)
	}
	return cmd.Wait()
}

var releaseMemory = debug.FreeOSMemory

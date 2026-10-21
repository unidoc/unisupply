// unisupply — Go Supply Chain Risk Assessment CLI
// by UniDoc (unidoc.io)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/unidoc/unisupply/internal/version"
	"github.com/unidoc/unisupply/pkg/facts"
	"github.com/unidoc/unisupply/pkg/netlog"
	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/policy"
	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/report"
	"github.com/unidoc/unisupply/pkg/runner"
	"github.com/unidoc/unisupply/pkg/scanner"

	flag "github.com/spf13/pflag"
)

// errPolicyViolation is returned when the dependency graph fails policy evaluation.
var errPolicyViolation = errors.New("policy violation")

// errScanFailed is returned when the scan failed or was interrupted but a report could still be written (scan_status.status
// is "failed" or "interrupted" in the JSON). The report is written first; the exit code is 4.
var errScanFailed = errors.New("scan failed")

// errTokenPrecondition is returned when --require-github-token is set but the
// token is missing, rejected, or could not be validated. Exit code 3 is
// reserved for this precondition failure so CI pipelines can distinguish it
// from a runtime error (1) or a policy violation (2). It is the runner's
// sentinel, because runner.Run is where a present token is validated.
var errTokenPrecondition = runner.ErrGithubTokenPrecondition

func main() {
	var (
		format                 string
		output                 string
		sbomOut                string
		analysisOut            string
		privateModules         string
		factsURL               string
		factsKeyFlag           string
		factsKeyFile           string
		verbose                bool
		noColor                bool
		moduleVersion          string
		responseHistory        bool
		gradeStdlib            bool
		strictArchived         bool
		calledPass             string
		directOnly             bool
		timeout                time.Duration
		showHelp               bool
		showVer                bool
		scanWorkflows          bool
		scanCI                 bool
		workflowPath           string
		githubToken            string
		nvdAPIKey              string
		requireGithubToken     bool
		policyFile             string
		policyPreset           string
		trustIndexURL          string
		trustIndexAllowPrivate bool
		progressMode           string
		networkLog             bool
		offlineMode            bool
	)

	flag.StringVarP(&format, "format", "f", "text", "Output format: text, json, pdf, sbom-cyclonedx, sbom-spdx")
	flag.StringVarP(&output, "output", "o", "", "Output file path (default: stdout for text/json/sbom, \"unisupply-report.pdf\" for pdf)")
	flag.StringVar(&sbomOut, "sbom-out", "", "Also write the CycloneDX SBOM of the same scan to this file, whatever --format is (one scan, two outputs)")
	flag.StringVar(&analysisOut, "analysis-out", "", "Also write the stored Analysis (JSON) of the same scan to this file; runner.Grade grades it again later without the module's files")
	flag.StringVar(&privateModules, "private-modules", "", "Comma-separated module path patterns (GOPRIVATE syntax) of private modules: never looked up (no proxy, GitHub or facts request carries their path) and not graded on upkeep. Replaces GOPRIVATE/GONOPROXY from the environment when set")
	flag.StringVar(&factsURL, "facts-url", "", "Read module and advisory facts from a gorisk facts API (e.g. https://gorisk.dev) instead of looking them up (env UNISUPPLY_FACTS_URL); the key comes from UNISUPPLY_FACTS_KEY or --facts-key-file")
	flag.StringVar(&factsKeyFile, "facts-key-file", "", "File holding the facts API key (gk_...); the env var UNISUPPLY_FACTS_KEY works too")
	flag.StringVar(&factsKeyFlag, "facts-key", "", "Refused: a flag value shows in the process list. Use UNISUPPLY_FACTS_KEY or --facts-key-file")
	_ = flag.CommandLine.MarkHidden("facts-key")
	flag.BoolVarP(&verbose, "verbose", "v", false, "Show detailed information for each dependency")
	flag.BoolVar(&noColor, "no-color", false, "Disable color output")
	flag.BoolVar(&directOnly, "direct-only", false, "Only analyze direct dependencies")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "HTTP request timeout")
	flag.BoolVarP(&showHelp, "help", "h", false, "Show help")
	flag.BoolVar(&showVer, "version", false, "Show version")
	flag.BoolVar(&scanWorkflows, "scan-workflows", false, "Scan GitHub Actions workflow files in .github/workflows/")
	flag.BoolVar(&scanCI, "scan-ci", false, "Scan CI/CD configuration (GitHub Actions, Dockerfile, Makefile)")
	flag.StringVar(&workflowPath, "workflow-path", ".github/workflows", "Path to workflow directory")
	flag.StringVar(&githubToken, "github-token", "", "GitHub API token for maintainer analysis (prefer set GITHUB_TOKEN env)")
	flag.StringVar(&nvdAPIKey, "nvd-api-key", "", "NVD API key for higher CVE severity lookup rate limits (prefer set the NVD_API_KEY env)")
	flag.BoolVar(&requireGithubToken, "require-github-token", false, "Exit code 3 if GitHub token is missing or invalid (for strict CI use)")
	flag.StringVar(&policyFile, "policy", "", "Path to policy JSON file for compliance checks")
	flag.StringVar(&policyPreset, "policy-preset", "", "Use a built-in policy preset: strict, moderate")
	flag.StringVar(&trustIndexURL, "trust-index-url", "", "UniDoc Trust Index API URL (e.g. http://localhost:8080)")
	flag.BoolVar(&trustIndexAllowPrivate, "trust-index-allow-private", false, "Allow --trust-index-url to target RFC1918/link-local addresses (e.g. self-hosted on a private network)")
	flag.StringVar(&progressMode, "progress", "auto", "Progress output: auto, plain, none")
	flag.BoolVar(&networkLog, "network-log", false, "Log every outbound HTTP request to stderr (verify the documented network contract)")
	flag.BoolVar(&offlineMode, "offline", false, "Make no network requests; scanners that need the network degrade to UNKNOWN with a warning")
	flag.StringVar(&moduleVersion, "module-version", "", "Published version of the scanned module (e.g. v1.4.0): grades the module itself too, from its own OSV advisories and archived/deprecated status")
	flag.BoolVar(&gradeStdlib, "grade-stdlib", false, "Let the Go standard library decide the letter (it is always listed, with the Go release it was matched against, but not graded by default: its findings follow the Go toolchain that runs the scan)")
	flag.BoolVar(&strictArchived, "strict-archived", false, "Make an archived flag that could not be read (GitHub rate limit without a token) make the grade Pending, instead of grading on what is known with a note")
	flag.StringVar(&calledPass, "called-pass", "auto", "When govulncheck's called pass runs: auto (only when it can change the letter; the imported pass always runs first), always (as before), never (imported pass only)")
	flag.BoolVar(&responseHistory, "response-history", false, "Look up how fast the project adopted its dependencies' fixes in the past (extra module proxy and OSV requests; needs --module-version)")

	flag.Parse()

	if showHelp {
		printUsage()
		os.Exit(0)
	}

	if showVer {
		fmt.Printf("unisupply v%s\n", version.String())
		if version.IsPreRelease() {
			fmt.Fprintln(os.Stderr, "[WARNING] pre-release build — not for production use")
		}
		os.Exit(0)
	}

	// GitHub token from env if not set via flag.
	if githubToken == "" {
		githubToken = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}

	// NVD API key from env if not set via flag.
	if nvdAPIKey == "" {
		nvdAPIKey = strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	}

	// Determine target path.
	path := "."
	if flag.NArg() > 0 {
		path = flag.Arg(0)
	}

	cfg := runConfig{
		path:                   path,
		format:                 format,
		output:                 output,
		sbomOut:                sbomOut,
		analysisOut:            analysisOut,
		privateModules:         privateModules,
		factsURL:               factsURL,
		factsKeyFlag:           factsKeyFlag,
		factsKeyFile:           factsKeyFile,
		verbose:                verbose,
		noColor:                noColor,
		moduleVersion:          moduleVersion,
		responseHistory:        responseHistory,
		gradeStdlib:            gradeStdlib,
		strictArchived:         strictArchived,
		calledPass:             calledPass,
		directOnly:             directOnly,
		timeout:                timeout,
		scanWorkflows:          scanWorkflows,
		scanCI:                 scanCI,
		workflowPath:           workflowPath,
		githubToken:            githubToken,
		nvdAPIKey:              nvdAPIKey,
		requireGithubToken:     requireGithubToken,
		policyFile:             policyFile,
		policyPreset:           policyPreset,
		trustIndexURL:          trustIndexURL,
		trustIndexAllowPrivate: trustIndexAllowPrivate,
		progressMode:           progressMode,
		networkLog:             networkLog,
		offlineMode:            offlineMode,
	}

	if err := run(&cfg); err != nil {
		// Policy violation should exit with code 2 for CI/CD integration.
		if errors.Is(err, errPolicyViolation) {
			os.Exit(2)
		}
		// A scan that failed or was interrupted, with its report written, exits with code 4.
		if errors.Is(err, errScanFailed) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(4)
		}
		// Token precondition failure exits with code 3.
		if errors.Is(err, errTokenPrecondition) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", cliError(err))
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", cliError(err))
		os.Exit(1)
	}
}

// cliError is what the CLI prints for a failure. A scan error leads with a reason code for library callers (gorisk), so
// the CLI prints the cause alone, as it did before the code existed.
func cliError(err error) error {
	var se *scanner.ScanError
	if errors.As(err, &se) && se.Err != nil {
		return se.Err
	}
	return err
}

type runConfig struct {
	path                   string
	format                 string
	output                 string
	sbomOut                string
	analysisOut            string
	privateModules         string
	factsURL               string
	factsKeyFlag           string
	factsKeyFile           string
	verbose                bool
	noColor                bool
	moduleVersion          string
	responseHistory        bool
	gradeStdlib            bool
	strictArchived         bool
	calledPass             string
	directOnly             bool
	timeout                time.Duration
	scanWorkflows          bool
	scanCI                 bool
	workflowPath           string
	githubToken            string
	nvdAPIKey              string
	requireGithubToken     bool
	policyFile             string
	policyPreset           string
	trustIndexURL          string
	trustIndexAllowPrivate bool
	progressMode           string
	networkLog             bool
	offlineMode            bool
}

func run(cfg *runConfig) error {
	// A malformed --module-version fails before anything is scanned: OSV would
	// otherwise be asked about a version no release has.
	if cfg.responseHistory && cfg.moduleVersion == "" {
		return fmt.Errorf("--response-history needs --module-version: the history is of the published module's releases")
	}
	calledPassMode, err := scanner.ParseCalledPassMode(cfg.calledPass)
	if err != nil {
		return fmt.Errorf("--called-pass: %w", err)
	}
	if cfg.moduleVersion != "" {
		if err := scanner.CheckModuleVersion(cfg.moduleVersion); err != nil {
			return fmt.Errorf("--module-version: %w", err)
		}
	}

	// --require-github-token: fail fast (exit 3) when no token is present.
	// This is the cheap, offline half of the precondition; whether a present
	// token is accepted by GitHub is checked by runner.Run, after the
	// dependency graph is resolved and before any scanner runs.
	if cfg.requireGithubToken && cfg.githubToken == "" {
		return fmt.Errorf("%w: --require-github-token is set but no GitHub token was provided (set --github-token or GITHUB_TOKEN)", errTokenPrecondition)
	}

	// Both are checked before the scan: a typo must not cost a whole scan, nor end in an empty output file.
	switch cfg.format {
	case "text", "json", "pdf", "sbom-cyclonedx", "sbom-spdx":
	default:
		return fmt.Errorf("unknown format: %s (supported: text, json, pdf, sbom-cyclonedx, sbom-spdx)", cfg.format)
	}
	switch cfg.policyPreset {
	case "", "strict", "moderate":
	default:
		return fmt.Errorf("unknown policy preset: %s (supported: strict, moderate)", cfg.policyPreset)
	}
	factsStore, err := factsStoreFor(cfg)
	if err != nil {
		return err
	}
	if cfg.analysisOut != "" && (cfg.analysisOut == cfg.output || cfg.analysisOut == cfg.sbomOut) {
		return fmt.Errorf("--analysis-out names the same file as --output or --sbom-out (%s): it would overwrite it", cfg.analysisOut)
	}
	if cfg.sbomOut != "" && cfg.sbomOut == cfg.output {
		return fmt.Errorf("--sbom-out and --output name the same file (%s): the SBOM would overwrite the report", cfg.output)
	}

	if cfg.policyFile != "" && cfg.policyPreset != "" {
		fmt.Fprintf(os.Stderr, "warning: --policy-preset %q ignored — --policy %q takes precedence\n",
			cfg.policyPreset, cfg.policyFile)
	}

	if cfg.offlineMode {
		// --trust-index-url names a specific endpoint the user asked to reach,
		// so combining it with --offline is a contradiction, not a redundancy.
		if cfg.trustIndexURL != "" {
			return fmt.Errorf("--offline cannot be combined with --trust-index-url %q: the Trust Index is a network service", cfg.trustIndexURL)
		}
		// UniPDF validates its license over the network before rendering.
		// Without this guard the scan runs to completion and then dies at the
		// last step, leaving a 0-byte file where the report should be. Fail up
		// front and name the format that works.
		if cfg.format == "pdf" {
			return errors.New("--offline cannot be combined with --format pdf: PDF generation requires a UniDoc license check over the network; use --format text, json, or sbom-*")
		}
		// A token supplied alongside --offline is unused, not contradictory —
		// CI configs routinely set the token and the mode flag from separate
		// layers — so warn and continue rather than failing the run. The
		// wording must not claim the token is good: offline, there is no way
		// to know, and runner.Run skips the probe.
		if cfg.requireGithubToken {
			fmt.Fprintln(os.Stderr, "warning: --require-github-token is set and a token is present, but it was not validated because --offline means GitHub will not be contacted")
		}
	}

	mode, err := progress.ParseMode(cfg.progressMode)
	if err != nil {
		return err
	}

	if cfg.offlineMode {
		// Install the refusing transport before any request is issued, and
		// before netlog below, so netlog wraps the refusal and every refused
		// request still appears in the network log when both flags are set.
		// Same interception point as netlog, for the same reason: it is the
		// only one that also covers http.DefaultClient consumers.
		offline.Enable()
	}

	if cfg.networkLog {
		// Install the logging transport before any request is issued. This is
		// the single interception point: the hardened scanner client delegates
		// to http.DefaultTransport, as do dependencies that use
		// http.DefaultClient directly (x/vuln → vuln.go.dev, UniPDF →
		// cloud.unidoc.io).
		netlog.Enable(os.Stderr)

		// The TTY reporter repaints lines in place, which raw log lines would
		// corrupt. Downgrade auto to plain; an explicit --progress none stays
		// silent.
		if mode == progress.ModeAuto {
			mode = progress.ModePlain
		}
	}
	rep := progress.New(mode)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx = progress.WithReporter(ctx, rep)

	runOpts := runner.Options{
		Path:                   cfg.path,
		Timeout:                cfg.timeout,
		DirectOnly:             cfg.directOnly,
		GithubToken:            cfg.githubToken,
		NVDAPIKey:              cfg.nvdAPIKey,
		RequireGithubToken:     cfg.requireGithubToken,
		TrustIndexURL:          cfg.trustIndexURL,
		TrustIndexAllowPrivate: cfg.trustIndexAllowPrivate,
		ScanWorkflows:          cfg.scanWorkflows,
		ScanCI:                 cfg.scanCI,
		WorkflowPath:           cfg.workflowPath,
		SelfVersion:            cfg.moduleVersion,
		ResponseHistory:        cfg.responseHistory,
		GradeStdlib:            cfg.gradeStdlib,
		StrictArchivedStatus:   cfg.strictArchived,
		CalledPass:             calledPassMode,
		Facts:                  factsStore,
		PrivatePatterns:        privatePatterns(cfg.privateModules),
	}
	var scanResult *runner.Result
	var analysis *runner.Analysis
	if cfg.analysisOut != "" {
		scanResult, analysis, err = runner.RunAnalysed(ctx, runOpts)
	} else {
		scanResult, err = runner.Run(ctx, runOpts)
	}
	if err != nil {
		// A scan that could not start still leaves a machine-readable answer when JSON was asked for: the typed reason.
		if cfg.format == "json" {
			writeFailureJSON(cfg, err)
		}
		return err
	}

	if analysis != nil {
		if err := writeAnalysisFile(cfg.analysisOut, analysis); err != nil {
			return err
		}
	}

	// A module with nothing to scan and no published version to grade has no report. A policy is still evaluated: a gate
	// must not pass because there was nothing to look at.
	noReport := len(scanResult.Graph.Dependencies) == 0 && cfg.moduleVersion == ""
	if noReport {
		fmt.Fprintln(os.Stderr, "No dependencies found. Pass --module-version to grade the module itself.")
	}

	if !noReport {
		if err := writeReport(ctx, cfg, rep, scanResult); err != nil {
			return err
		}
		if cfg.sbomOut != "" {
			if err := writeSBOMFile(cfg.sbomOut, scanResult); err != nil {
				return err
			}
		}
	}

	if cfg.policyFile != "" || cfg.policyPreset != "" {
		if err := evaluatePolicy(cfg, rep, scanResult); err != nil {
			return err
		}
	}
	// The report is written either way; a failed or interrupted scan is said in its scan_status and by the exit code.
	if st := scanResult.ScanStatus; !noReport && (st.Status == scanner.StatusFailed || st.Status == scanner.StatusInterrupted) {
		return fmt.Errorf("%w: %s (%s)", errScanFailed, st.Reason, st.Detail)
	}
	return nil
}

// privatePatterns splits --private-modules; nil (the environment's GOPRIVATE and GONOPROXY apply) when it is empty.
func privatePatterns(flagValue string) []string {
	if strings.TrimSpace(flagValue) == "" {
		return nil
	}
	return strings.Split(flagValue, ",")
}

// factsStoreFor is the facts store the flags and environment ask for: nil without a facts URL. The key is never a flag value
// (it would show in the process list); it comes from --facts-key-file or UNISUPPLY_FACTS_KEY.
func factsStoreFor(cfg *runConfig) (facts.Store, error) {
	if cfg.factsKeyFlag != "" {
		return nil, errors.New("--facts-key is refused: a flag value shows in the process list; use UNISUPPLY_FACTS_KEY or --facts-key-file")
	}
	base := cfg.factsURL
	if base == "" {
		base = strings.TrimSpace(os.Getenv("UNISUPPLY_FACTS_URL"))
	}
	if base == "" {
		return nil, nil
	}
	if cfg.offlineMode {
		return nil, errors.New("--offline cannot be combined with a facts URL: the facts API is a network service")
	}
	key := strings.TrimSpace(os.Getenv("UNISUPPLY_FACTS_KEY"))
	if cfg.factsKeyFile != "" {
		b, err := os.ReadFile(cfg.factsKeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading --facts-key-file: %w", err)
		}
		key = strings.TrimSpace(string(b))
	}
	if key == "" {
		return nil, errors.New("a facts URL needs its API key: set UNISUPPLY_FACTS_KEY or --facts-key-file")
	}
	store, err := facts.NewHTTPStore(base, key)
	if err != nil {
		return nil, err
	}
	return store, nil
}

// writeAnalysisFile writes the Analysis as JSON, for --analysis-out.
func writeAnalysisFile(path string, an *runner.Analysis) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating analysis file: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(an); err != nil {
		f.Close()
		return fmt.Errorf("writing analysis: %w", err)
	}
	return f.Close()
}

// writeSBOMFile writes the CycloneDX SBOM of the scan to path, for --sbom-out.
func writeSBOMFile(path string, scanResult *runner.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating SBOM file: %w", err)
	}
	opts := report.SBOMOptions{GoVersion: scanResult.GoMod.GoVersion, Grade: scanResult.Grade}
	if err := report.WriteCycloneDX(scanResult.Graph, scanResult.ProjectScore, opts, f); err != nil {
		f.Close()
		return fmt.Errorf("writing SBOM: %w", err)
	}
	return f.Close()
}

// writeFailureJSON writes the JSON of a scan that could not start (no go.mod, the dependency graph cannot be resolved,
// ...) to the output file or stdout, with the typed reason in scan_status. It does nothing for an error that is not a
// scan failure (a bad flag, the token precondition) and never turns a failure into a second one: the error the caller
// returns is the one that is reported.
func writeFailureJSON(cfg *runConfig, cause error) {
	var se *scanner.ScanError
	if !errors.As(cause, &se) {
		return
	}
	w := os.Stdout
	if cfg.output != "" {
		f, err := os.Create(cfg.output)
		if err != nil {
			return
		}
		defer f.Close()
		w = f
	}
	_ = report.WriteJSONFailure(cause, w)
}

// writeReport renders the scan result in the format asked for.
func writeReport(ctx context.Context, cfg *runConfig, rep progress.Reporter, scanResult *runner.Result) (err error) {
	gomod := scanResult.GoMod
	graph := scanResult.Graph
	projectScore := scanResult.ProjectScore
	ciReport := scanResult.CIReport
	gradeResult := scanResult.Grade
	stdlibVulns := scanResult.StdlibVulns
	integrityReport := scanResult.IntegrityReport

	// Generate output.
	writer := os.Stdout
	if cfg.output != "" {
		f, err := os.Create(cfg.output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		writer = f
	} else if cfg.format == "pdf" && cfg.output == "" {
		cfg.output = "unisupply-report.pdf"
	}

	sbomOpts := report.SBOMOptions{GoVersion: gomod.GoVersion, Grade: gradeResult}

	// Only open a progress stage when the report writer targets a file (or
	// is the PDF writer, which writes to its own file). Streaming text/json/
	// sbom to stdout shares the terminal with the spinner line on stderr —
	// keeping the stage open visibly collides the two streams.
	stageReport := cfg.output != "" || cfg.format == "pdf"
	if stageReport {
		rep.Stage(fmt.Sprintf("Generating %s report", cfg.format))
	}
	if cfg.format == "pdf" && os.Getenv("UNIDOC_LICENSE_API_KEY") == "" {
		fmt.Fprintln(os.Stderr, "unisupply: --format pdf without UNIDOC_LICENSE_API_KEY generates a watermarked PDF.")
		fmt.Fprintln(os.Stderr, "  With a key, PDF generation contacts cloud.unidoc.io (metered license API).")
		fmt.Fprintln(os.Stderr, "  Use --format text for fully offline, keyless output.")
	}

	switch cfg.format {
	case "text":
		err = report.WriteText(graph, projectScore, &report.TextOptions{
			Scan:            scanResult.ScanInfo,
			NoColor:         cfg.noColor,
			Verbose:         cfg.verbose,
			Writer:          writer,
			CIReport:        ciReport,
			IntegrityReport: integrityReport,
			Grade:           gradeResult,
			StdlibVulns:     stdlibVulns,
		})
	case "json":
		err = report.WriteJSON(graph, projectScore, report.JSONOptions{
			Scan:            scanResult.ScanInfo,
			ScanStatus:      &scanResult.ScanStatus,
			GoVersion:       gomod.GoVersion,
			CIReport:        ciReport,
			IntegrityReport: integrityReport,
			Grade:           gradeResult,
			StdlibVulns:     stdlibVulns,
		}, writer)
	case "pdf":
		err = report.WritePDF(ctx, graph, projectScore, report.PDFOptions{
			OutputPath:      cfg.output,
			GoVersion:       gomod.GoVersion,
			CIReport:        ciReport,
			IntegrityReport: integrityReport,
			Grade:           gradeResult,
			StdlibVulns:     stdlibVulns,
		})
	case "sbom-cyclonedx":
		err = report.WriteCycloneDX(graph, projectScore, sbomOpts, writer)
	case "sbom-spdx":
		err = report.WriteSPDX(graph, projectScore, sbomOpts, writer)
	default:
		return fmt.Errorf("unknown format: %s (supported: text, json, pdf, sbom-cyclonedx, sbom-spdx)", cfg.format)
	}

	if err != nil {
		return err
	}
	if stageReport {
		if cfg.output != "" {
			rep.Done("%s", cfg.output)
		} else {
			rep.Done("")
		}
	}

	return nil
}

// evaluatePolicy checks the grade and the scan result against the policy; a violation is errPolicyViolation.
func evaluatePolicy(cfg *runConfig, rep progress.Reporter, scanResult *runner.Result) error {
	projectScore := scanResult.ProjectScore
	gradeResult := scanResult.Grade
	maintainers := scanResult.Maintainers
	typosquats := scanResult.Typosquats
	ciReport := scanResult.CIReport
	integrityReport := scanResult.IntegrityReport
	var err error
	{
		rep.Stage("Evaluating policy")
		var pol *policy.Policy

		if cfg.policyFile != "" {
			pol, err = policy.LoadPolicy(cfg.policyFile)
			if err != nil {
				return fmt.Errorf("loading policy: %w", err)
			}
		} else {
			switch cfg.policyPreset {
			case "strict":
				pol = policy.DefaultStrictPolicy()
			case "moderate":
				pol = policy.DefaultModeratePolicy()
			default:
				return fmt.Errorf("unknown policy preset: %s (supported: strict, moderate)", cfg.policyPreset)
			}
		}

		result := pol.Evaluate(policy.EvalInput{
			ProjectScore:    projectScore,
			Grade:           gradeResult,
			Maintainers:     maintainers,
			Typosquats:      typosquats,
			CIReport:        ciReport,
			IntegrityReport: integrityReport,
		})

		if result.Pass {
			rep.Done("pass")
		} else {
			rep.Done("fail")
		}
		fmt.Fprint(os.Stderr, result.FormatText(cfg.noColor))

		if !result.Pass {
			return errPolicyViolation
		}
	}

	return nil
}

func printUsage() {
	fmt.Printf("unisupply v%s — Go Supply Chain Risk Assessment\n", version.String())
	fmt.Println("by UniDoc (unidoc.io)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  unisupply [flags] [path]")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  unisupply                                    # Analyze current directory")
	fmt.Println("  unisupply ./myproject                        # Analyze specific project")
	fmt.Println("  unisupply -f json -o report.json             # JSON output to file")
	fmt.Println("  unisupply -f pdf                             # Generate PDF report")
	fmt.Println("  unisupply -f json -o r.json --sbom-out s.json # JSON report and CycloneDX SBOM from one scan")
	fmt.Println("  unisupply -f sbom-cyclonedx -o sbom.json     # CycloneDX SBOM")
	fmt.Println("  unisupply -f sbom-spdx -o sbom.spdx.json     # SPDX SBOM")
	fmt.Println("  unisupply --module-version v1.4.0            # Also grade the module itself at a published version")
	fmt.Println("  unisupply --scan-workflows                   # Include GitHub Actions audit")
	fmt.Println("  unisupply --scan-ci                          # Full CI/CD pipeline scan")
	fmt.Println("  unisupply --policy policy.json               # Evaluate against policy file")
	fmt.Println("  unisupply --policy-preset strict             # Use strict built-in policy")
	fmt.Println("  unisupply --require-github-token ./          # Fail (exit 3) if token missing or invalid")
	fmt.Println("  unisupply --progress plain                   # Plain log-style progress on stderr")
	fmt.Println("  unisupply --progress none -f json            # Silent run; JSON to stdout")
	fmt.Println("  unisupply --network-log 2>net.log            # Log every outbound request to stderr")
	fmt.Println("  unisupply --offline                          # Air-gapped scan; no network requests")
	fmt.Println("  unisupply --offline --network-log 2>net.log  # Prove the scan made no requests")
	fmt.Println()
	fmt.Println("Exit codes:")
	fmt.Println("  0  Success. Without --policy or --policy-preset the exit code ignores the grade: a grade of F or Pending still exits 0")
	fmt.Println("  1  Runtime error (I/O failure, parse error, etc.)")
	fmt.Println("  2  Policy violation — one or more policy rules failed (max_grade: a grade worse than the limit, or Pending unless allow_pending)")
	fmt.Println("  3  Token precondition failure — --require-github-token set but token missing, rejected, or could not be validated")
	fmt.Println("  4  The scan failed or was interrupted, and the report was still written: scan_status.status is \"failed\" or \"interrupted\" with the typed")
	fmt.Println("     reason in scan_status.reason. A policy violation (2) takes precedence. A scan that could not start (1) writes the same scan_status")
	fmt.Println("     as the whole JSON when --format json is used")
	fmt.Println()
	fmt.Println("Flags:")
	flag.PrintDefaults()
}

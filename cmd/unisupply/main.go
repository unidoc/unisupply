// unisupply — Go Supply Chain Risk Assessment CLI
// by UniDoc (unidoc.io)
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/unidoc/unisupply/internal/version"
	"github.com/unidoc/unisupply/pkg/netlog"
	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/policy"
	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/report"
	"github.com/unidoc/unisupply/pkg/runner"

	flag "github.com/spf13/pflag"
)

// errPolicyViolation is returned when the dependency graph fails policy evaluation.
var errPolicyViolation = errors.New("policy violation")

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
		verbose                bool
		noColor                bool
		minRisk                int
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
		debugScoring           bool
		networkLog             bool
		offlineMode            bool
	)

	flag.StringVarP(&format, "format", "f", "text", "Output format: text, json, pdf, sbom-cyclonedx, sbom-spdx")
	flag.StringVarP(&output, "output", "o", "", "Output file path (default: stdout for text/json/sbom, \"unisupply-report.pdf\" for pdf)")
	flag.BoolVarP(&verbose, "verbose", "v", false, "Show detailed information for each dependency")
	flag.BoolVar(&noColor, "no-color", false, "Disable color output")
	flag.IntVar(&minRisk, "min-risk", 0, "Only show dependencies with risk score >= this value (0-100)")
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
	flag.BoolVar(&debugScoring, "debug-scoring", false, "Include diagnostic debug_scoring block in output (non-normative; for miscalibration reports)")

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
		verbose:                verbose,
		noColor:                noColor,
		minRisk:                minRisk,
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
		debugScoring:           debugScoring,
		networkLog:             networkLog,
		offlineMode:            offlineMode,
	}

	if err := run(&cfg); err != nil {
		// Policy violation should exit with code 2 for CI/CD integration.
		if errors.Is(err, errPolicyViolation) {
			os.Exit(2)
		}
		// Token precondition failure exits with code 3.
		if errors.Is(err, errTokenPrecondition) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type runConfig struct {
	path                   string
	format                 string
	output                 string
	verbose                bool
	noColor                bool
	minRisk                int
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
	debugScoring           bool
	networkLog             bool
	offlineMode            bool
}

func run(cfg *runConfig) error {
	// --require-github-token: fail fast (exit 3) when no token is present.
	// This is the cheap, offline half of the precondition; whether a present
	// token is accepted by GitHub is checked by runner.Run, after the
	// dependency graph is resolved and before any scanner runs.
	if cfg.requireGithubToken && cfg.githubToken == "" {
		return fmt.Errorf("%w: --require-github-token is set but no GitHub token was provided (set --github-token or GITHUB_TOKEN)", errTokenPrecondition)
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

	scanResult, err := runner.Run(ctx, runner.Options{
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
		DebugScoring:           cfg.debugScoring,
	})
	if err != nil {
		return err
	}

	if len(scanResult.Graph.Dependencies) == 0 {
		fmt.Fprintln(os.Stderr, "No dependencies found.")
		return nil
	}

	gomod := scanResult.GoMod
	graph := scanResult.Graph
	projectScore := scanResult.ProjectScore
	ciReport := scanResult.CIReport
	takeovers := scanResult.Takeovers
	stdlibVulns := scanResult.StdlibVulns
	maintainers := scanResult.Maintainers
	typosquats := scanResult.Typosquats
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

	sbomOpts := report.SBOMOptions{GoVersion: gomod.GoVersion}

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
			NoColor:         cfg.noColor,
			Verbose:         cfg.verbose,
			MinRisk:         cfg.minRisk,
			Writer:          writer,
			CIReport:        ciReport,
			IntegrityReport: integrityReport,
			Takeovers:       takeovers,
			StdlibVulns:     stdlibVulns,
		})
	case "json":
		err = report.WriteJSON(graph, projectScore, report.JSONOptions{
			GoVersion:       gomod.GoVersion,
			CIReport:        ciReport,
			IntegrityReport: integrityReport,
			Takeovers:       takeovers,
		}, writer)
	case "pdf":
		err = report.WritePDF(ctx, graph, projectScore, report.PDFOptions{
			OutputPath:      cfg.output,
			GoVersion:       gomod.GoVersion,
			CIReport:        ciReport,
			IntegrityReport: integrityReport,
			Takeovers:       takeovers,
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

	if cfg.policyFile != "" || cfg.policyPreset != "" {
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
	fmt.Println("  unisupply -f pdf                             # Generate PDF risk report")
	fmt.Println("  unisupply -f sbom-cyclonedx -o sbom.json     # CycloneDX SBOM")
	fmt.Println("  unisupply -f sbom-spdx -o sbom.spdx.json     # SPDX SBOM")
	fmt.Println("  unisupply --min-risk 50                      # Only show medium+ risk deps")
	fmt.Println("  unisupply --scan-workflows                   # Include GitHub Actions audit")
	fmt.Println("  unisupply --scan-ci                          # Full CI/CD pipeline scan")
	fmt.Println("  unisupply --policy policy.json               # Evaluate against policy file")
	fmt.Println("  unisupply --policy-preset strict             # Use strict built-in policy")
	fmt.Println("  unisupply --require-github-token ./          # Fail (exit 3) if token missing or invalid")
	fmt.Println("  unisupply --progress plain                   # Plain log-style progress on stderr")
	fmt.Println("  unisupply --progress none -f json            # Silent run; JSON to stdout")
	fmt.Println("  unisupply --debug-scoring -f json            # Emit non-normative debug_scoring block")
	fmt.Println("  unisupply --network-log 2>net.log            # Log every outbound request to stderr")
	fmt.Println("  unisupply --offline                          # Air-gapped scan; no network requests")
	fmt.Println("  unisupply --offline --network-log 2>net.log  # Prove the scan made no requests")
	fmt.Println()
	fmt.Println("Exit codes:")
	fmt.Println("  0  Clean scan — no policy violations, token precondition satisfied")
	fmt.Println("  1  Runtime error (I/O failure, parse error, etc.)")
	fmt.Println("  2  Policy violation — one or more policy rules failed")
	fmt.Println("  3  Token precondition failure — --require-github-token set but token missing, rejected, or could not be validated")
	fmt.Println()
	fmt.Println("Flags:")
	flag.PrintDefaults()
}

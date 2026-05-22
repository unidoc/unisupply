// unisupply — Go Supply Chain Risk Assessment CLI
// by UniDoc (unidoc.io)
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/unidoc/unisupply/internal/version"
	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/policy"
	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/report"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"

	flag "github.com/spf13/pflag"
)

// errPolicyViolation is returned when the dependency graph fails policy evaluation.
var errPolicyViolation = errors.New("policy violation")

func main() {
	var (
		format        string
		output        string
		verbose       bool
		noColor       bool
		minRisk       int
		directOnly    bool
		timeout       time.Duration
		showHelp      bool
		showVer       bool
		scanWorkflows bool
		scanCI        bool
		workflowPath  string
		githubToken   string
		policyFile    string
		policyPreset  string
		trustIndexURL string
		progressMode  string
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
	flag.StringVar(&githubToken, "github-token", "", "GitHub API token for maintainer analysis (or set GITHUB_TOKEN env)")
	flag.StringVar(&policyFile, "policy", "", "Path to policy JSON file for compliance checks")
	flag.StringVar(&policyPreset, "policy-preset", "", "Use a built-in policy preset: strict, moderate")
	flag.StringVar(&trustIndexURL, "trust-index-url", "", "UniDoc Trust Index API URL (e.g. http://localhost:8080)")
	flag.StringVar(&progressMode, "progress", "auto", "Progress output: auto, plain, none")

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
		githubToken = os.Getenv("GITHUB_TOKEN")
	}

	// Determine target path.
	path := "."
	if flag.NArg() > 0 {
		path = flag.Arg(0)
	}

	cfg := runConfig{
		path:          path,
		format:        format,
		output:        output,
		verbose:       verbose,
		noColor:       noColor,
		minRisk:       minRisk,
		directOnly:    directOnly,
		timeout:       timeout,
		scanWorkflows: scanWorkflows,
		scanCI:        scanCI,
		workflowPath:  workflowPath,
		githubToken:   githubToken,
		policyFile:    policyFile,
		policyPreset:  policyPreset,
		trustIndexURL: trustIndexURL,
		progressMode:  progressMode,
	}

	if err := run(&cfg); err != nil {
		// Policy violation should exit with code 2 for CI/CD integration.
		if errors.Is(err, errPolicyViolation) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type runConfig struct {
	path          string
	format        string
	output        string
	verbose       bool
	noColor       bool
	minRisk       int
	directOnly    bool
	timeout       time.Duration
	scanWorkflows bool
	scanCI        bool
	workflowPath  string
	githubToken   string
	policyFile    string
	policyPreset  string
	trustIndexURL string
	progressMode  string
}

func run(cfg *runConfig) error {
	mode, err := progress.ParseMode(cfg.progressMode)
	if err != nil {
		return err
	}
	rep := progress.New(mode)
	ctx := progress.WithReporter(context.Background(), rep)

	rep.Stage("Parsing go.mod")
	gomodPath, err := parser.FindGoMod(cfg.path)
	if err != nil {
		return err
	}
	gomod, err := parser.ParseGoMod(gomodPath)
	if err != nil {
		return err
	}
	projectDir := filepath.Dir(gomodPath)
	rep.Done("%s", gomodPath)

	rep.Stage("Resolving dependency graph")
	graph, warnings, err := resolver.Resolve(ctx, gomodPath, cfg.directOnly)
	if err != nil {
		return fmt.Errorf("resolving dependencies: %w", err)
	}
	for _, w := range warnings {
		rep.Warn("%s", w)
	}
	rep.Done("%d modules", len(graph.Dependencies))

	if len(graph.Dependencies) == 0 {
		fmt.Fprintln(os.Stderr, "No dependencies found.")
		return nil
	}

	rep.Stage("Scanning vulnerabilities (govulncheck)")
	vulns, vulnWarnings, err := scanner.ScanVulns(ctx, projectDir)
	if err != nil {
		rep.Warn("Vulnerability scan failed: %v", err)
	}
	for _, w := range vulnWarnings {
		rep.Warn("%s", w)
	}
	rep.Done("%d affected modules", len(vulns))

	rep.Stage("Checking maintenance health")
	maintScanner := scanner.NewMaintenanceScanner(cfg.timeout)
	maintenance, err := maintScanner.ScanAll(ctx, graph)
	if err != nil {
		rep.Warn("Some maintenance checks failed: %v", err)
	}
	rep.Done("")

	rep.Stage("Analyzing maintainers (GitHub API)")
	maintainerScanner := scanner.NewMaintainerScanner(cfg.timeout, cfg.githubToken)
	maintainers := maintainerScanner.ScanAll(ctx, graph)
	rep.Done("")

	rep.Stage("Detecting typosquats")
	typosquatScanner := scanner.NewTyposquatScanner()
	typosquats := typosquatScanner.ScanAll(ctx, graph)
	rep.Done("%d suspicious", len(typosquats))

	rep.Stage("Scoring resilience")
	resilienceScanner := scanner.NewResilienceScanner(cfg.timeout)
	resilience := resilienceScanner.ScanAll(ctx, graph, maintainers)
	rep.Done("")

	rep.Stage("Assessing AI-generation risk")
	aiGenScanner := scanner.NewAIGenScanner()
	aiGenRisks := aiGenScanner.ScanAll(ctx, graph, maintainers, resilience)
	rep.Done("%d flagged", len(aiGenRisks))

	var trustIndex map[string]*scanner.TrustIndexEntry
	trustClient := scanner.NewTrustIndexClient(cfg.trustIndexURL, cfg.timeout)
	if trustClient != nil {
		rep.Stage("Querying Trust Index")
		var tiErr error
		trustIndex, tiErr = trustClient.LookupAll(ctx, graph)
		if tiErr != nil {
			rep.Warn("Trust Index lookup failed: %v", tiErr)
		}
		rep.Done("%d entries", len(trustIndex))
	}

	rep.Stage("Computing risk scores")
	projectScore := scorer.ScoreAll(scorer.ScoreInput{
		Graph:       graph,
		Vulns:       vulns,
		Maintenance: maintenance,
		Maintainers: maintainers,
		Typosquats:  typosquats,
		Resilience:  resilience,
		AIGenRisks:  aiGenRisks,
		TrustIndex:  trustIndex,
	})
	rep.Done("")

	var ciReport *scanner.CIReport
	if cfg.scanWorkflows || cfg.scanCI {
		rep.Stage("Auditing CI/CD pipelines")
		ciScanner := scanner.NewCIScanner()

		wfPath := cfg.workflowPath
		if !filepath.IsAbs(wfPath) {
			wfPath = filepath.Join(projectDir, wfPath)
		}

		ciReport, err = ciScanner.ScanWorkflows(ctx, wfPath)
		if err != nil {
			rep.Warn("Workflow scanning failed: %v", err)
		}

		if cfg.scanCI && ciReport != nil {
			buildFindings := ciScanner.ScanBuildFiles(ctx, projectDir)
			ciReport.BuildFindings = buildFindings
			ciReport.TotalFindings += len(buildFindings)
		}
		rep.Done("")
	}

	// Collect takeover candidates.
	var takeovers []*scanner.MaintainerInfo
	for _, mi := range maintainers {
		if mi.TakeoverCandidate {
			takeovers = append(takeovers, mi)
		}
	}

	// Separate stdlib vulns from module vulns.
	var stdlibVulns []scanner.Vulnerability
	if stdlibList, ok := vulns["stdlib"]; ok {
		stdlibVulns = stdlibList
		delete(vulns, "stdlib")
	}

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
	switch cfg.format {
	case "text":
		err = report.WriteText(graph, projectScore, &report.TextOptions{
			NoColor:     cfg.noColor,
			Verbose:     cfg.verbose,
			MinRisk:     cfg.minRisk,
			Writer:      writer,
			CIReport:    ciReport,
			Takeovers:   takeovers,
			StdlibVulns: stdlibVulns,
		})
	case "json":
		err = report.WriteJSON(graph, projectScore, report.JSONOptions{
			GoVersion: gomod.GoVersion,
			CIReport:  ciReport,
			Takeovers: takeovers,
		}, writer)
	case "pdf":
		err = report.WritePDF(ctx, graph, projectScore, report.PDFOptions{
			OutputPath: cfg.output,
			GoVersion:  gomod.GoVersion,
			CIReport:   ciReport,
			Takeovers:  takeovers,
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
			ProjectScore: projectScore,
			Maintainers:  maintainers,
			Typosquats:   typosquats,
			CIReport:     ciReport,
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
	fmt.Println("  unisupply                                  # Analyze current directory")
	fmt.Println("  unisupply ./myproject                       # Analyze specific project")
	fmt.Println("  unisupply -f json -o report.json            # JSON output to file")
	fmt.Println("  unisupply -f pdf                            # Generate PDF risk report")
	fmt.Println("  unisupply -f sbom-cyclonedx -o sbom.json    # CycloneDX SBOM")
	fmt.Println("  unisupply -f sbom-spdx -o sbom.spdx.json    # SPDX SBOM")
	fmt.Println("  unisupply --min-risk 50                     # Only show medium+ risk deps")
	fmt.Println("  unisupply --scan-workflows                  # Include GitHub Actions audit")
	fmt.Println("  unisupply --scan-ci                         # Full CI/CD pipeline scan")
	fmt.Println("  unisupply --policy policy.json              # Evaluate against policy file")
	fmt.Println("  unisupply --policy-preset strict            # Use strict built-in policy")
	fmt.Println("  unisupply --progress plain                  # Plain log-style progress on stderr")
	fmt.Println("  unisupply --progress none -f json           # Silent run; JSON to stdout")
	fmt.Println()
	fmt.Println("Flags:")
	flag.PrintDefaults()
}

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
}

func run(cfg *runConfig) error {
	// 1. Find go.mod.
	gomodPath, err := parser.FindGoMod(cfg.path)
	if err != nil {
		return err
	}

	gomod, err := parser.ParseGoMod(gomodPath)
	if err != nil {
		return err
	}

	projectDir := filepath.Dir(gomodPath)

	// 2. Resolve dependency graph.
	graph, warnings, err := resolver.Resolve(gomodPath, cfg.directOnly)
	if err != nil {
		return fmt.Errorf("resolving dependencies: %w", err)
	}

	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
	}

	if len(graph.Dependencies) == 0 {
		fmt.Println("No dependencies found.")
		return nil
	}

	// 3. Vulnerability scan (via govulncheck).
	vulns, vulnWarnings, err := scanner.ScanVulns(context.Background(), projectDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Vulnerability scan failed: %v\n", err)
	}
	for _, w := range vulnWarnings {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
	}

	// 4. Maintenance health check.
	maintScanner := scanner.NewMaintenanceScanner(cfg.timeout)
	maintenance, err := maintScanner.ScanAll(graph)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Some maintenance checks failed: %v\n", err)
	}

	// 5. Maintainer analysis (GitHub API).
	maintainerScanner := scanner.NewMaintainerScanner(cfg.timeout, cfg.githubToken)
	maintainers := maintainerScanner.ScanAll(graph)

	// 6. Typosquatting detection.
	typosquatScanner := scanner.NewTyposquatScanner()
	typosquats := typosquatScanner.ScanAll(graph)

	// 7. Resilience scoring (release cadence, governance).
	resilienceScanner := scanner.NewResilienceScanner(cfg.timeout)
	resilience := resilienceScanner.ScanAll(graph, maintainers)

	// 8. AI-generated code risk detection.
	aiGenScanner := scanner.NewAIGenScanner()
	aiGenRisks := aiGenScanner.ScanAll(graph, maintainers, resilience)

	// 9. Trust Index lookup (if unitrust API is configured).
	var trustIndex map[string]*scanner.TrustIndexEntry
	trustClient := scanner.NewTrustIndexClient(cfg.trustIndexURL, cfg.timeout)
	if trustClient != nil {
		var tiErr error
		trustIndex, tiErr = trustClient.LookupAll(graph)
		if tiErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Trust Index lookup failed: %v\n", tiErr)
		}
	}

	// 10. Score everything.
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

	// 8. CI/CD scanning (if enabled).
	var ciReport *scanner.CIReport
	if cfg.scanWorkflows || cfg.scanCI {
		ciScanner := scanner.NewCIScanner()

		wfPath := cfg.workflowPath
		if !filepath.IsAbs(wfPath) {
			wfPath = filepath.Join(projectDir, wfPath)
		}

		ciReport, err = ciScanner.ScanWorkflows(wfPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Workflow scanning failed: %v\n", err)
		}

		if cfg.scanCI && ciReport != nil {
			buildFindings := ciScanner.ScanBuildFiles(projectDir)
			ciReport.BuildFindings = buildFindings
			ciReport.TotalFindings += len(buildFindings)
		}
	}

	// 9. Collect takeover candidates.
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

	// 10. Generate output.
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
		err = report.WritePDF(graph, projectScore, report.PDFOptions{
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

	// 11. Policy evaluation (if enabled).
	if cfg.policyFile != "" || cfg.policyPreset != "" {
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
	fmt.Println()
	fmt.Println("Flags:")
	flag.PrintDefaults()
}

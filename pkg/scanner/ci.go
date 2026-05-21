package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/progress"
)

// CIRiskLevel categorizes CI/CD risk.
type CIRiskLevel string

// CI/CD risk level bands. Mirrors scorer.RiskLevel for consistency in reports.
const (
	CIRiskLow      CIRiskLevel = "LOW"
	CIRiskMedium   CIRiskLevel = "MEDIUM"
	CIRiskHigh     CIRiskLevel = "HIGH"
	CIRiskCritical CIRiskLevel = "CRITICAL"
)

// CIFinding represents a single CI/CD security finding.
type CIFinding struct {
	Category    string      `json:"category"`
	Severity    CIRiskLevel `json:"severity"`
	Description string      `json:"description"`
	File        string      `json:"file"`
	Line        int         `json:"line,omitempty"`
	Remediation string      `json:"remediation"`
}

// WorkflowRisk holds the risk assessment for a single workflow file.
type WorkflowRisk struct {
	Name     string      `json:"name"`
	FilePath string      `json:"file_path"`
	Score    int         `json:"score"`
	Level    CIRiskLevel `json:"level"`
	Findings []CIFinding `json:"findings"`
}

// CIReport holds the full CI/CD risk assessment.
type CIReport struct {
	Workflows         []*WorkflowRisk `json:"workflows,omitempty"`
	BuildFindings     []CIFinding     `json:"build_findings,omitempty"`
	OverallScore      int             `json:"overall_score"`
	OverallLevel      CIRiskLevel     `json:"overall_level"`
	UnpinnedActions   int             `json:"unpinned_actions"`
	ThirdPartyActions int             `json:"third_party_actions"`
	TotalFindings     int             `json:"total_findings"`
}

// CIScanner scans CI/CD configuration for security risks.
type CIScanner struct{}

// NewCIScanner creates a new CI/CD scanner.
func NewCIScanner() *CIScanner {
	return &CIScanner{}
}

// ScanWorkflows scans GitHub Actions workflow files.
func (cs *CIScanner) ScanWorkflows(ctx context.Context, workflowDir string) (*CIReport, error) {
	rep := progress.From(ctx)
	report := &CIReport{}

	rep.Step("parsing workflows in %s", workflowDir)
	workflows, err := parser.ParseAllWorkflows(workflowDir)
	if err != nil {
		return nil, fmt.Errorf("parsing workflows: %w", err)
	}

	if len(workflows) == 0 {
		return report, nil
	}

	for i, wf := range workflows {
		wr := cs.analyzeWorkflow(wf)
		report.Workflows = append(report.Workflows, wr)
		report.TotalFindings += len(wr.Findings)
		rep.Progress(i+1, len(workflows))
	}

	// Count unpinned and third-party actions.
	for _, wr := range report.Workflows {
		for _, f := range wr.Findings {
			switch f.Category {
			case "unpinned_action":
				report.UnpinnedActions++
			case "third_party_action":
				report.ThirdPartyActions++
			}
		}
	}

	report.OverallScore = cs.computeOverallCIScore(report)
	report.OverallLevel = ciLevelFromScore(report.OverallScore)

	return report, nil
}

// ScanBuildFiles scans Dockerfiles, Makefiles, and build scripts.
func (cs *CIScanner) ScanBuildFiles(ctx context.Context, projectDir string) []CIFinding {
	rep := progress.From(ctx)
	var findings []CIFinding

	// Scan Dockerfiles.
	dockerfiles := findFiles(projectDir, "Dockerfile*")
	for _, df := range dockerfiles {
		rep.Step("Dockerfile %s", filepath.Base(df))
		findings = append(findings, cs.scanDockerfile(df)...)
	}

	// Scan Makefiles.
	makefiles := findFiles(projectDir, "Makefile*")
	for _, mf := range makefiles {
		rep.Step("Makefile %s", filepath.Base(mf))
		findings = append(findings, cs.scanMakefile(mf)...)
	}

	// Scan shell scripts.
	scripts := findFiles(projectDir, "*.sh")
	for _, s := range scripts {
		rep.Step("shell script %s", filepath.Base(s))
		findings = append(findings, cs.scanShellScript(s)...)
	}

	return findings
}

func (cs *CIScanner) analyzeWorkflow(wf *parser.Workflow) *WorkflowRisk {
	wr := &WorkflowRisk{
		Name:     wf.Name,
		FilePath: wf.FilePath,
	}

	// Check top-level permissions.
	if wf.Permissions.IsWriteAll {
		wr.Findings = append(wr.Findings, CIFinding{
			Category:    "excessive_permissions",
			Severity:    CIRiskHigh,
			Description: "Workflow has write-all permissions",
			File:        wf.FilePath,
			Remediation: "Use granular permissions (e.g., contents: read) instead of write-all",
		})
	}

	for _, job := range wf.Jobs {
		// Check self-hosted runners.
		if job.IsSelfHosted {
			wr.Findings = append(wr.Findings, CIFinding{
				Category:    "self_hosted_runner",
				Severity:    CIRiskMedium,
				Description: fmt.Sprintf("Job uses self-hosted runner: %s", job.RunsOn),
				File:        wf.FilePath,
				Remediation: "Ensure self-hosted runners are hardened and isolated. Consider using GitHub-hosted runners for public repos.",
			})
		}

		// Check job-level permissions.
		if job.Permissions.IsWriteAll {
			wr.Findings = append(wr.Findings, CIFinding{
				Category:    "excessive_permissions",
				Severity:    CIRiskHigh,
				Description: fmt.Sprintf("Job '%s' has write-all permissions", job.Name),
				File:        wf.FilePath,
				Remediation: "Restrict job permissions to minimum required",
			})
		}

		for _, step := range job.Steps {
			// Analyze action references.
			if step.Uses != "" {
				cs.analyzeAction(step, wf.FilePath, wr)
			}

			// Check for secrets in environment variables passed to run steps.
			cs.checkSecretsExposure(step, wf.FilePath, wr)

			// Check run steps for dangerous patterns.
			if step.Run != "" {
				cs.checkDangerousRun(step, wf.FilePath, wr)
			}
		}
	}

	// Compute workflow score.
	wr.Score = cs.computeWorkflowScore(wr.Findings)
	wr.Level = ciLevelFromScore(wr.Score)

	return wr
}

func (cs *CIScanner) analyzeAction(step parser.WorkflowStep, filePath string, wr *WorkflowRisk) {
	ref := parser.ParseActionRef(step.Uses)
	if ref == nil || ref.IsLocal {
		return
	}

	// Check if action is pinned to a SHA.
	if !ref.IsPinned {
		severity := CIRiskMedium
		desc := fmt.Sprintf("Action '%s' uses floating tag '%s' instead of pinned SHA", step.Uses, ref.Version)
		if !parser.IsOfficialAction(ref) {
			severity = CIRiskHigh
			desc = fmt.Sprintf("Third-party action '%s' uses floating tag '%s' — vulnerable to tag hijacking", step.Uses, ref.Version)
		}

		wr.Findings = append(wr.Findings, CIFinding{
			Category:    "unpinned_action",
			Severity:    severity,
			Description: desc,
			File:        filePath,
			Remediation: fmt.Sprintf("Pin to a full SHA: %s/%s@<commit-sha>", ref.Owner, ref.Repo),
		})
	}

	// Check for third-party (non-official) actions.
	if !parser.IsOfficialAction(ref) {
		wr.Findings = append(wr.Findings, CIFinding{
			Category:    "third_party_action",
			Severity:    CIRiskLow,
			Description: fmt.Sprintf("Third-party action: %s/%s (verify author trustworthiness)", ref.Owner, ref.Repo),
			File:        filePath,
			Remediation: "Audit the action source code and verify the author's identity",
		})
	}
}

func (cs *CIScanner) checkSecretsExposure(step parser.WorkflowStep, filePath string, wr *WorkflowRisk) {
	secretPattern := regexp.MustCompile(`\$\{\{\s*secrets\.`)

	// Check env vars for secrets passed to untrusted steps.
	for key, val := range step.Env {
		if secretPattern.MatchString(val) {
			ref := parser.ParseActionRef(step.Uses)
			if ref != nil && !parser.IsOfficialAction(ref) {
				wr.Findings = append(wr.Findings, CIFinding{
					Category:    "secrets_exposure",
					Severity:    CIRiskCritical,
					Description: fmt.Sprintf("Secret passed via env '%s' to third-party action '%s'", key, step.Uses),
					File:        filePath,
					Remediation: "Avoid passing secrets to third-party actions. Use OIDC tokens or scoped tokens instead.",
				})
			}
		}
	}

	// Check 'with' inputs for secrets.
	for key, val := range step.With {
		if secretPattern.MatchString(val) {
			ref := parser.ParseActionRef(step.Uses)
			if ref != nil && !parser.IsOfficialAction(ref) {
				wr.Findings = append(wr.Findings, CIFinding{
					Category:    "secrets_exposure",
					Severity:    CIRiskHigh,
					Description: fmt.Sprintf("Secret passed via input '%s' to third-party action '%s'", key, step.Uses),
					File:        filePath,
					Remediation: "Audit the action to ensure secrets are handled securely",
				})
			}
		}
	}
}

func (cs *CIScanner) checkDangerousRun(step parser.WorkflowStep, filePath string, wr *WorkflowRisk) {
	run := step.Run

	// Check for curl | bash pattern.
	curlBash := regexp.MustCompile(`curl\s+.*\|\s*(ba)?sh`)
	if curlBash.MatchString(run) {
		wr.Findings = append(wr.Findings, CIFinding{
			Category:    "dangerous_command",
			Severity:    CIRiskHigh,
			Description: "Step pipes curl output to shell (curl | bash pattern)",
			File:        filePath,
			Remediation: "Download scripts first, verify checksums, then execute",
		})
	}

	// Check for wget | bash.
	wgetBash := regexp.MustCompile(`wget\s+.*\|\s*(ba)?sh`)
	if wgetBash.MatchString(run) {
		wr.Findings = append(wr.Findings, CIFinding{
			Category:    "dangerous_command",
			Severity:    CIRiskHigh,
			Description: "Step pipes wget output to shell",
			File:        filePath,
			Remediation: "Download scripts first, verify checksums, then execute",
		})
	}

	// Check for downloading binaries without checksum verification.
	downloadNoVerify := regexp.MustCompile(`(curl|wget)\s+.*-[oO]\s+\S+`)
	checksumVerify := regexp.MustCompile(`(sha256sum|shasum|md5sum|gpg\s+--verify)`)
	if downloadNoVerify.MatchString(run) && !checksumVerify.MatchString(run) {
		wr.Findings = append(wr.Findings, CIFinding{
			Category:    "unverified_download",
			Severity:    CIRiskMedium,
			Description: "Step downloads a file without checksum verification",
			File:        filePath,
			Remediation: "Add checksum verification after downloading binaries",
		})
	}

	// Check for GitHub event context injection (expression injection).
	exprInjection := regexp.MustCompile(`\$\{\{\s*github\.event\.(issue|pull_request|comment)`)
	if exprInjection.MatchString(run) {
		wr.Findings = append(wr.Findings, CIFinding{
			Category:    "expression_injection",
			Severity:    CIRiskCritical,
			Description: "Step uses untrusted GitHub event data in a run command (expression injection risk)",
			File:        filePath,
			Remediation: "Use an intermediate environment variable instead of inline expressions with untrusted data",
		})
	}
}

// scanDockerfile checks a Dockerfile for supply chain risks.
func (cs *CIScanner) scanDockerfile(path string) []CIFinding {
	var findings []CIFinding

	f, err := os.Open(path) //#nosec G304 -- caller-supplied build file path is the scanner's input contract
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Check for unpinned base images.
		if strings.HasPrefix(strings.ToUpper(line), "FROM ") {
			image := strings.Fields(line)[1]
			if !strings.Contains(image, "@sha256:") {
				if strings.Contains(image, ":latest") || !strings.Contains(image, ":") {
					findings = append(findings, CIFinding{
						Category:    "unpinned_base_image",
						Severity:    CIRiskMedium,
						Description: fmt.Sprintf("Base image '%s' is not pinned to a digest", image),
						File:        path,
						Line:        lineNum,
						Remediation: "Pin the base image to a SHA256 digest: image@sha256:<digest>",
					})
				}
			}
		}

		// Check for curl | bash in RUN commands.
		if strings.HasPrefix(strings.ToUpper(line), "RUN ") {
			curlBash := regexp.MustCompile(`curl\s+.*\|\s*(ba)?sh`)
			if curlBash.MatchString(line) {
				findings = append(findings, CIFinding{
					Category:    "dangerous_command",
					Severity:    CIRiskHigh,
					Description: "Dockerfile pipes curl output to shell",
					File:        path,
					Line:        lineNum,
					Remediation: "Download scripts, verify checksums, then execute in separate steps",
				})
			}
		}

		// Check for ADD with remote URLs (prefer COPY + explicit download).
		if strings.HasPrefix(strings.ToUpper(line), "ADD ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && (strings.HasPrefix(fields[1], "http://") || strings.HasPrefix(fields[1], "https://")) {
				findings = append(findings, CIFinding{
					Category:    "remote_add",
					Severity:    CIRiskMedium,
					Description: fmt.Sprintf("ADD fetches remote URL: %s", fields[1]),
					File:        path,
					Line:        lineNum,
					Remediation: "Use RUN curl/wget with checksum verification instead of ADD for remote resources",
				})
			}
		}
	}

	return findings
}

// scanMakefile checks a Makefile for supply chain risks.
func (cs *CIScanner) scanMakefile(path string) []CIFinding {
	var findings []CIFinding

	f, err := os.Open(path) //#nosec G304 -- caller-supplied build file path is the scanner's input contract
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		curlBash := regexp.MustCompile(`curl\s+.*\|\s*(ba)?sh`)
		if curlBash.MatchString(line) {
			findings = append(findings, CIFinding{
				Category:    "dangerous_command",
				Severity:    CIRiskHigh,
				Description: "Makefile pipes curl output to shell",
				File:        path,
				Line:        lineNum,
				Remediation: "Download scripts, verify checksums, then execute",
			})
		}

		wgetBash := regexp.MustCompile(`wget\s+.*\|\s*(ba)?sh`)
		if wgetBash.MatchString(line) {
			findings = append(findings, CIFinding{
				Category:    "dangerous_command",
				Severity:    CIRiskHigh,
				Description: "Makefile pipes wget output to shell",
				File:        path,
				Line:        lineNum,
				Remediation: "Download scripts, verify checksums, then execute",
			})
		}
	}

	return findings
}

// scanShellScript checks shell scripts for supply chain risks.
func (cs *CIScanner) scanShellScript(path string) []CIFinding {
	var findings []CIFinding

	f, err := os.Open(path) //#nosec G304 -- caller-supplied build file path is the scanner's input contract
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		curlBash := regexp.MustCompile(`curl\s+.*\|\s*(ba)?sh`)
		if curlBash.MatchString(line) {
			findings = append(findings, CIFinding{
				Category:    "dangerous_command",
				Severity:    CIRiskHigh,
				Description: "Script pipes curl output to shell",
				File:        path,
				Line:        lineNum,
				Remediation: "Download scripts, verify checksums, then execute",
			})
		}
	}

	return findings
}

func (cs *CIScanner) computeWorkflowScore(findings []CIFinding) int {
	if len(findings) == 0 {
		return 0
	}

	score := 0
	for _, f := range findings {
		switch f.Severity {
		case CIRiskCritical:
			score += 30
		case CIRiskHigh:
			score += 20
		case CIRiskMedium:
			score += 10
		case CIRiskLow:
			score += 5
		}
	}

	if score > 100 {
		score = 100
	}
	return score
}

func (cs *CIScanner) computeOverallCIScore(report *CIReport) int {
	if len(report.Workflows) == 0 && len(report.BuildFindings) == 0 {
		return 0
	}

	maxScore := 0
	for _, wr := range report.Workflows {
		if wr.Score > maxScore {
			maxScore = wr.Score
		}
	}

	// Add build findings to the score.
	buildScore := 0
	for _, f := range report.BuildFindings {
		switch f.Severity {
		case CIRiskCritical:
			buildScore += 30
		case CIRiskHigh:
			buildScore += 20
		case CIRiskMedium:
			buildScore += 10
		case CIRiskLow:
			buildScore += 5
		}
	}
	if buildScore > 100 {
		buildScore = 100
	}

	// Overall is the max of workflow and build scores.
	if buildScore > maxScore {
		maxScore = buildScore
	}

	return maxScore
}

func ciLevelFromScore(score int) CIRiskLevel {
	switch {
	case score >= 76:
		return CIRiskCritical
	case score >= 51:
		return CIRiskHigh
	case score >= 26:
		return CIRiskMedium
	default:
		return CIRiskLow
	}
}

func findFiles(dir, pattern string) []string {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil
	}
	return matches
}

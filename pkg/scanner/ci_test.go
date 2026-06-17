package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/unidoc/unisupply/pkg/parser"
)

// TestCIScanner_AnalyzeWorkflow_Clean tests a minimal workflow with no findings.
func TestCIScanner_AnalyzeWorkflow_Clean(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs:     make(map[string]*parser.WorkflowJob),
	}

	result := cs.analyzeWorkflow(wf)

	if result.Score != 0 {
		t.Errorf("expected score 0, got %d", result.Score)
	}
	if result.Level != CIRiskLow {
		t.Errorf("expected level LOW, got %s", result.Level)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

// TestCIScanner_AnalyzeWorkflow_WriteAll tests top-level write-all permissions.
func TestCIScanner_AnalyzeWorkflow_WriteAll(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Permissions: parser.WorkflowPermissions{
			IsWriteAll: true,
		},
		Jobs: make(map[string]*parser.WorkflowJob),
	}

	result := cs.analyzeWorkflow(wf)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Category != "excessive_permissions" {
		t.Errorf("expected category 'excessive_permissions', got %s", f.Category)
	}
	if f.Severity != CIRiskHigh {
		t.Errorf("expected severity HIGH, got %s", f.Severity)
	}
}

// TestCIScanner_AnalyzeWorkflow_JobWriteAll tests job-level write-all permissions.
func TestCIScanner_AnalyzeWorkflow_JobWriteAll(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Permissions: parser.WorkflowPermissions{
					IsWriteAll: true,
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Category != "excessive_permissions" {
		t.Errorf("expected category 'excessive_permissions', got %s", f.Category)
	}
	if f.Severity != CIRiskHigh {
		t.Errorf("expected severity HIGH, got %s", f.Severity)
	}
}

// TestCIScanner_AnalyzeWorkflow_SelfHosted tests self-hosted runner detection.
func TestCIScanner_AnalyzeWorkflow_SelfHosted(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name:         "test-job",
				RunsOn:       "self-hosted",
				IsSelfHosted: true,
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Category != "self_hosted_runner" {
		t.Errorf("expected category 'self_hosted_runner', got %s", f.Category)
	}
	if f.Severity != CIRiskMedium {
		t.Errorf("expected severity MEDIUM, got %s", f.Severity)
	}
}

// TestCIScanner_AnalyzeWorkflow_UnpinnedOfficial tests floating tag on official action.
func TestCIScanner_AnalyzeWorkflow_UnpinnedOfficial(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Checkout",
						Uses: "actions/checkout@v4",
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Category != "unpinned_action" {
		t.Errorf("expected category 'unpinned_action', got %s", f.Category)
	}
	if f.Severity != CIRiskMedium {
		t.Errorf("expected severity MEDIUM, got %s", f.Severity)
	}
}

// TestCIScanner_AnalyzeWorkflow_UnpinnedThirdParty tests floating tag on third-party action.
func TestCIScanner_AnalyzeWorkflow_UnpinnedThirdParty(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Random action",
						Uses: "random/action@v1",
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Should have 2 findings: unpinned_action (HIGH) and third_party_action (LOW)
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	// Check for unpinned_action with HIGH severity
	found := false
	for _, f := range result.Findings {
		if f.Category == "unpinned_action" && f.Severity == CIRiskHigh {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected unpinned_action finding with HIGH severity")
	}
}

// TestCIScanner_AnalyzeWorkflow_PinnedAction tests SHA-pinned action (no unpinned finding).
func TestCIScanner_AnalyzeWorkflow_PinnedAction(t *testing.T) {
	cs := NewCIScanner()
	sha := "356a192b7913b04c54574d18c28d46e6395428ab" // 40 hex chars
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Checkout",
						Uses: "actions/checkout@" + sha,
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Should have no unpinned_action finding for official action
	for _, f := range result.Findings {
		if f.Category == "unpinned_action" {
			t.Errorf("expected no unpinned_action finding for SHA-pinned official action")
		}
	}
}

// TestCIScanner_AnalyzeWorkflow_ThirdPartyAction tests third-party action marking.
func TestCIScanner_AnalyzeWorkflow_ThirdPartyAction(t *testing.T) {
	cs := NewCIScanner()
	sha := "356a192b7913b04c54574d18c28d46e6395428ab"
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Third party",
						Uses: "random/action@" + sha,
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Should have third_party_action finding (LOW)
	found := false
	for _, f := range result.Findings {
		if f.Category == "third_party_action" && f.Severity == CIRiskLow {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected third_party_action finding with LOW severity")
	}
}

// TestCIScanner_AnalyzeWorkflow_SecretsEnvToThirdParty tests secrets in env to third-party action.
func TestCIScanner_AnalyzeWorkflow_SecretsEnvToThirdParty(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Random action",
						Uses: "random/action@v1",
						Env: map[string]string{
							"TOKEN": "${{ secrets.MY_TOKEN }}",
						},
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Should have secrets_exposure with CRITICAL severity
	found := false
	for _, f := range result.Findings {
		if f.Category == "secrets_exposure" && f.Severity == CIRiskCritical {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected secrets_exposure finding with CRITICAL severity")
	}
}

// TestCIScanner_AnalyzeWorkflow_SecretsWithToThirdParty tests secrets in 'with' to third-party action.
func TestCIScanner_AnalyzeWorkflow_SecretsWithToThirdParty(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Random action",
						Uses: "random/action@v1",
						With: map[string]string{
							"token": "${{ secrets.MY_TOKEN }}",
						},
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Should have secrets_exposure with HIGH severity
	found := false
	for _, f := range result.Findings {
		if f.Category == "secrets_exposure" && f.Severity == CIRiskHigh {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected secrets_exposure finding with HIGH severity")
	}
}

// TestCIScanner_AnalyzeWorkflow_SecretsToOfficial tests secrets to official action (no finding).
func TestCIScanner_AnalyzeWorkflow_SecretsToOfficial(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Official action",
						Uses: "actions/upload-artifact@v3",
						Env: map[string]string{
							"TOKEN": "${{ secrets.MY_TOKEN }}",
						},
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Should have no secrets_exposure finding for official action
	for _, f := range result.Findings {
		if f.Category == "secrets_exposure" {
			t.Errorf("expected no secrets_exposure finding for official action")
		}
	}
}

// TestCIScanner_AnalyzeWorkflow_CurlBash tests curl | bash pattern detection.
func TestCIScanner_AnalyzeWorkflow_CurlBash(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Download and run",
						Run:  "curl http://example.com/script.sh | bash",
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Should have dangerous_command finding
	found := false
	for _, f := range result.Findings {
		if f.Category == "dangerous_command" && f.Severity == CIRiskHigh {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected dangerous_command finding with HIGH severity for curl | bash")
	}
}

// TestCIScanner_AnalyzeWorkflow_WgetBash tests wget | bash pattern detection.
func TestCIScanner_AnalyzeWorkflow_WgetBash(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Download and run",
						Run:  "wget http://example.com/script.sh | sh",
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Should have dangerous_command finding
	found := false
	for _, f := range result.Findings {
		if f.Category == "dangerous_command" && f.Severity == CIRiskHigh {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected dangerous_command finding with HIGH severity for wget | sh")
	}
}

// TestCIScanner_AnalyzeWorkflow_ExpressionInjection tests expression injection detection.
func TestCIScanner_AnalyzeWorkflow_ExpressionInjection(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Vulnerable step",
						Run:  "echo ${{ github.event.issue.title }}",
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Should have expression_injection finding with CRITICAL severity
	found := false
	for _, f := range result.Findings {
		if f.Category == "expression_injection" && f.Severity == CIRiskCritical {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected expression_injection finding with CRITICAL severity")
	}
}

// TestCIScanner_ScanDockerfile_UnpinnedLatest tests unpinned base image detection.
func TestCIScanner_ScanDockerfile_UnpinnedLatest(t *testing.T) {
	tempDir := t.TempDir()
	dockerfile := filepath.Join(tempDir, "Dockerfile")

	content := "FROM ubuntu:latest\nRUN apt-get update\n"
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write dockerfile: %v", err)
	}

	cs := NewCIScanner()
	findings := cs.scanDockerfile(dockerfile)

	found := false
	for _, f := range findings {
		if f.Category == "unpinned_base_image" && f.Severity == CIRiskMedium {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected unpinned_base_image finding with MEDIUM severity")
	}
}

// TestCIScanner_ScanDockerfile_Pinned tests pinned base image (no finding).
func TestCIScanner_ScanDockerfile_Pinned(t *testing.T) {
	tempDir := t.TempDir()
	dockerfile := filepath.Join(tempDir, "Dockerfile")

	content := "FROM ubuntu@sha256:abc123def456\nRUN apt-get update\n"
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write dockerfile: %v", err)
	}

	cs := NewCIScanner()
	findings := cs.scanDockerfile(dockerfile)

	for _, f := range findings {
		if f.Category == "unpinned_base_image" {
			t.Errorf("expected no unpinned_base_image finding for pinned image")
		}
	}
}

// TestCIScanner_ScanDockerfile_CurlBash tests curl | bash in Dockerfile.
func TestCIScanner_ScanDockerfile_CurlBash(t *testing.T) {
	tempDir := t.TempDir()
	dockerfile := filepath.Join(tempDir, "Dockerfile")

	content := "FROM ubuntu:20.04\nRUN curl http://example.com/script.sh | bash\n"
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write dockerfile: %v", err)
	}

	cs := NewCIScanner()
	findings := cs.scanDockerfile(dockerfile)

	found := false
	for _, f := range findings {
		if f.Category == "dangerous_command" && f.Severity == CIRiskHigh {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected dangerous_command finding with HIGH severity for curl | bash")
	}
}

// TestCIScanner_ScanMakefile_CurlBash tests curl | bash in Makefile.
func TestCIScanner_ScanMakefile_CurlBash(t *testing.T) {
	tempDir := t.TempDir()
	makefile := filepath.Join(tempDir, "Makefile")

	content := ".PHONY: install\ninstall:\n\tcurl http://example.com/install.sh | sh\n"
	if err := os.WriteFile(makefile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write makefile: %v", err)
	}

	cs := NewCIScanner()
	findings := cs.scanMakefile(makefile)

	found := false
	for _, f := range findings {
		if f.Category == "dangerous_command" && f.Severity == CIRiskHigh {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected dangerous_command finding with HIGH severity for curl | sh")
	}
}

// TestCIScanner_ScanShellScript_CurlBash tests curl | bash in shell script.
func TestCIScanner_ScanShellScript_CurlBash(t *testing.T) {
	tempDir := t.TempDir()
	script := filepath.Join(tempDir, "install.sh")

	content := "#!/bin/bash\ncurl http://example.com/install.sh | bash\n"
	if err := os.WriteFile(script, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	cs := NewCIScanner()
	findings := cs.scanShellScript(script)

	found := false
	for _, f := range findings {
		if f.Category == "dangerous_command" && f.Severity == CIRiskHigh {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected dangerous_command finding with HIGH severity for curl | bash")
	}
}

// TestComputeWorkflowScore tests score computation from findings.
func TestComputeWorkflowScore(t *testing.T) {
	tests := []struct {
		name     string
		findings []CIFinding
		expected int
	}{
		{
			name:     "no findings",
			findings: []CIFinding{},
			expected: 0,
		},
		{
			name: "one low finding",
			findings: []CIFinding{
				{Severity: CIRiskLow},
			},
			expected: 5,
		},
		{
			name: "one medium finding",
			findings: []CIFinding{
				{Severity: CIRiskMedium},
			},
			expected: 10,
		},
		{
			name: "one high finding",
			findings: []CIFinding{
				{Severity: CIRiskHigh},
			},
			expected: 20,
		},
		{
			name: "one critical finding",
			findings: []CIFinding{
				{Severity: CIRiskCritical},
			},
			expected: 30,
		},
		{
			name: "multiple findings sum",
			findings: []CIFinding{
				{Severity: CIRiskCritical},
				{Severity: CIRiskCritical},
				{Severity: CIRiskHigh},
			},
			expected: 80, // 30 + 30 + 20
		},
		{
			name: "score capped at 100",
			findings: []CIFinding{
				{Severity: CIRiskCritical},
				{Severity: CIRiskCritical},
				{Severity: CIRiskCritical},
				{Severity: CIRiskCritical},
			},
			expected: 100, // 30 * 4 = 120, capped at 100
		},
	}

	cs := NewCIScanner()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cs.computeWorkflowScore(tt.findings)
			if result != tt.expected {
				t.Errorf("expected score %d, got %d", tt.expected, result)
			}
		})
	}
}

// TestCILevelFromScore tests risk level determination from score.
func TestCILevelFromScore(t *testing.T) {
	tests := []struct {
		score    int
		expected CIRiskLevel
	}{
		{0, CIRiskLow},
		{25, CIRiskLow},
		{26, CIRiskMedium},
		{50, CIRiskMedium},
		{51, CIRiskHigh},
		{75, CIRiskHigh},
		{76, CIRiskCritical},
		{100, CIRiskCritical},
	}

	for _, tt := range tests {
		t.Run("score_"+string(rune(tt.score)), func(t *testing.T) {
			result := ciLevelFromScore(tt.score)
			if result != tt.expected {
				t.Errorf("score %d: expected %s, got %s", tt.score, tt.expected, result)
			}
		})
	}
}

// TestCIScanner_ScanWorkflows_Integration tests full workflow scanning.
func TestCIScanner_ScanWorkflows_Integration(t *testing.T) {
	tempDir := t.TempDir()
	workflowDir := filepath.Join(tempDir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		t.Fatalf("failed to create workflow dir: %v", err)
	}

	workflowFile := filepath.Join(workflowDir, "test.yml")
	content := `
name: Test
on: push
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	if err := os.WriteFile(workflowFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	cs := NewCIScanner()
	report, err := cs.ScanWorkflows(context.Background(), workflowDir)
	if err != nil {
		t.Fatalf("ScanWorkflows failed: %v", err)
	}

	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if len(report.Workflows) != 1 {
		t.Errorf("expected 1 workflow, got %d", len(report.Workflows))
	}
}

// TestCIScanner_ScanBuildFiles_Integration tests full build file scanning.
func TestCIScanner_ScanBuildFiles_Integration(t *testing.T) {
	tempDir := t.TempDir()
	dockerfile := filepath.Join(tempDir, "Dockerfile")

	content := "FROM ubuntu:latest\nRUN apt-get update\n"
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write dockerfile: %v", err)
	}

	cs := NewCIScanner()
	findings := cs.ScanBuildFiles(context.Background(), tempDir)

	found := false
	for _, f := range findings {
		if f.Category == "unpinned_base_image" && f.Severity == CIRiskMedium {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected unpinned_base_image finding in build files")
	}
}

// TestCIScanner_AnalyzeWorkflow_DownloadNoVerify tests download without checksum verification.
func TestCIScanner_AnalyzeWorkflow_DownloadNoVerify(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Download binary",
						Run:  "curl -o /tmp/binary http://example.com/binary",
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	found := false
	for _, f := range result.Findings {
		if f.Category == "unverified_download" && f.Severity == CIRiskMedium {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected unverified_download finding with MEDIUM severity")
	}
}

// TestCIScanner_AnalyzeWorkflow_DownloadWithVerify tests download with checksum verification (no finding).
func TestCIScanner_AnalyzeWorkflow_DownloadWithVerify(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Download and verify",
						Run:  "curl -o /tmp/binary http://example.com/binary && sha256sum /tmp/binary",
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	for _, f := range result.Findings {
		if f.Category == "unverified_download" {
			t.Errorf("expected no unverified_download finding when checksum is verified")
		}
	}
}

// TestCIScanner_AnalyzeWorkflow_LocalAction tests local action (no findings).
func TestCIScanner_AnalyzeWorkflow_LocalAction(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Local action",
						Uses: "./.github/actions/my-action",
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Local actions should not generate unpinned or third-party findings
	for _, f := range result.Findings {
		if f.Category == "unpinned_action" || f.Category == "third_party_action" {
			t.Errorf("expected no unpinned/third-party findings for local action")
		}
	}
}

// TestCIScanner_ScanDockerfile_MultipleVulnerabilities tests multiple findings in one Dockerfile.
func TestCIScanner_ScanDockerfile_MultipleVulnerabilities(t *testing.T) {
	tempDir := t.TempDir()
	dockerfile := filepath.Join(tempDir, "Dockerfile")

	content := `FROM ubuntu:latest
RUN curl http://example.com/script.sh | bash
ADD http://example.com/resource /tmp/
`
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write dockerfile: %v", err)
	}

	cs := NewCIScanner()
	findings := cs.scanDockerfile(dockerfile)

	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
}

// TestComputeOverallCIScore tests overall score computation.
func TestComputeOverallCIScore(t *testing.T) {
	cs := NewCIScanner()

	tests := []struct {
		name        string
		workflows   []*WorkflowRisk
		buildScore  []CIFinding
		expectedMax int
	}{
		{
			name:        "empty report",
			workflows:   []*WorkflowRisk{},
			buildScore:  []CIFinding{},
			expectedMax: 0,
		},
		{
			name: "single workflow score",
			workflows: []*WorkflowRisk{
				{Score: 50},
			},
			buildScore:  []CIFinding{},
			expectedMax: 50,
		},
		{
			name: "build findings take precedence",
			workflows: []*WorkflowRisk{
				{Score: 30},
			},
			buildScore: []CIFinding{
				{Severity: CIRiskHigh},
				{Severity: CIRiskHigh},
				{Severity: CIRiskHigh},
			},
			expectedMax: 60, // 3 * 20 = 60 > 30
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &CIReport{
				Workflows:     tt.workflows,
				BuildFindings: tt.buildScore,
			}
			result := cs.computeOverallCIScore(report)
			if result != tt.expectedMax {
				t.Errorf("expected overall score %d, got %d", tt.expectedMax, result)
			}
		})
	}
}

// TestCIScanner_ScanBuildFiles_NonExistentFile tests handling of missing files.
func TestCIScanner_ScanBuildFiles_NonExistentDir(t *testing.T) {
	cs := NewCIScanner()
	findings := cs.ScanBuildFiles(context.Background(), "/nonexistent/path")

	// Should return empty slice, not error
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nonexistent dir, got %d", len(findings))
	}
}

// TestCIScanner_AnalyzeWorkflow_DockerAction tests docker action handling.
func TestCIScanner_AnalyzeWorkflow_DockerAction(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Docker action",
						Uses: "docker://ubuntu:latest",
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Docker actions are considered official
	for _, f := range result.Findings {
		if f.Category == "third_party_action" {
			t.Errorf("expected no third_party_action finding for docker action")
		}
	}
}

// TestCIReport_Counters tests unpinned and third-party action counters in report.
func TestCIReport_Counters(t *testing.T) {
	tempDir := t.TempDir()
	workflowDir := filepath.Join(tempDir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		t.Fatalf("failed to create workflow dir: %v", err)
	}

	workflowFile := filepath.Join(workflowDir, "test.yml")
	content := `
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: random/action@v1
`
	if err := os.WriteFile(workflowFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	cs := NewCIScanner()
	report, err := cs.ScanWorkflows(context.Background(), workflowDir)
	if err != nil {
		t.Fatalf("ScanWorkflows failed: %v", err)
	}

	// Should count unpinned actions
	if report.UnpinnedActions < 2 {
		t.Errorf("expected at least 2 unpinned actions, got %d", report.UnpinnedActions)
	}
	// Should count third-party actions
	if report.ThirdPartyActions < 1 {
		t.Errorf("expected at least 1 third-party action, got %d", report.ThirdPartyActions)
	}
}

// TestCIScanner_AnalyzeWorkflow_InvalidActionRef tests handling of invalid action refs.
func TestCIScanner_AnalyzeWorkflow_InvalidActionRef(t *testing.T) {
	cs := NewCIScanner()
	wf := &parser.Workflow{
		Name:     "test",
		FilePath: "test.yml",
		Jobs: map[string]*parser.WorkflowJob{
			"test-job": {
				Name: "test-job",
				Steps: []parser.WorkflowStep{
					{
						Name: "Invalid action",
						Uses: "invalid-action-ref",
					},
				},
			},
		},
	}

	result := cs.analyzeWorkflow(wf)

	// Should not panic and return no findings for invalid refs
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for invalid action ref, got %d", len(result.Findings))
	}
}

// TestCIScanner_ScanMakefile_WgetBash tests wget | bash in Makefile.
func TestCIScanner_ScanMakefile_WgetBash(t *testing.T) {
	tempDir := t.TempDir()
	makefile := filepath.Join(tempDir, "Makefile")

	content := ".PHONY: build\nbuild:\n\twget http://example.com/install.sh | sh\n"
	if err := os.WriteFile(makefile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write makefile: %v", err)
	}

	cs := NewCIScanner()
	findings := cs.scanMakefile(makefile)

	found := false
	for _, f := range findings {
		if f.Category == "dangerous_command" && f.Severity == CIRiskHigh {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected dangerous_command finding with HIGH severity for wget | sh")
	}
}

// TestCIScanner_ScanDockerfile_ADDRemoteURL tests ADD with remote URL detection.
func TestCIScanner_ScanDockerfile_ADDRemoteURL(t *testing.T) {
	tempDir := t.TempDir()
	dockerfile := filepath.Join(tempDir, "Dockerfile")

	content := "FROM ubuntu:20.04\nADD http://example.com/resource /tmp/\n"
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write dockerfile: %v", err)
	}

	cs := NewCIScanner()
	findings := cs.scanDockerfile(dockerfile)

	found := false
	for _, f := range findings {
		if f.Category == "remote_add" && f.Severity == CIRiskMedium {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected remote_add finding with MEDIUM severity")
	}
}

// TestCIScanner_FindFiles_MultiplePatterns tests finding multiple files with pattern.
func TestCIScanner_FindFiles_MultipleDockerfiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create multiple dockerfiles
	files := []string{"Dockerfile", "Dockerfile.prod", "Dockerfile.dev"}
	for _, file := range files {
		path := filepath.Join(tempDir, file)
		if err := os.WriteFile(path, []byte("FROM ubuntu:latest\n"), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", file, err)
		}
	}

	cs := NewCIScanner()
	findings := cs.ScanBuildFiles(context.Background(), tempDir)

	// Should find findings in all Dockerfile variants
	if len(findings) < 3 {
		t.Errorf("expected at least 3 findings for 3 Dockerfiles, got %d", len(findings))
	}
}

// TestFindFiles_SkipsSymlink confirms findFiles never returns symlink paths.
func TestFindFiles_SkipsSymlink(t *testing.T) {
	dir := t.TempDir()

	real := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(real, []byte("FROM alpine\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "Dockerfile.link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks not supported on this platform:", err)
	}

	got := findFiles(dir, "Dockerfile*")
	for _, f := range got {
		fi, err := os.Lstat(f)
		if err != nil {
			t.Fatalf("Lstat(%s): %v", f, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			t.Errorf("findFiles returned symlink %s", f)
		}
	}
	if len(got) != 1 {
		t.Errorf("expected 1 real file, got %d: %v", len(got), got)
	}
}

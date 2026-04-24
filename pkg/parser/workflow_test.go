// Package parser — workflow_test.go tests GitHub Actions workflow parsing.
package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestParseWorkflow_Complete tests parsing a full workflow with all fields.
func TestParseWorkflow_Complete(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Test Workflow
permissions: write-all
on:
  push:
    branches:
      - main
jobs:
  job1:
    name: Job One
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
        env:
          KEY: value
      - name: Run build
        run: make build
  job2:
    name: Job Two
    runs-on: [self-hosted, linux]
    steps:
      - name: Test
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	if wf == nil {
		t.Fatal("ParseWorkflow() returned nil")
	}

	if wf.Name != "Test Workflow" {
		t.Errorf("Name = %q, want %q", wf.Name, "Test Workflow")
	}

	if wf.FilePath != workflowPath {
		t.Errorf("FilePath = %q, want %q", wf.FilePath, workflowPath)
	}

	if !wf.Permissions.IsWriteAll {
		t.Error("IsWriteAll = false, want true")
	}

	if len(wf.Jobs) != 2 {
		t.Fatalf("len(Jobs) = %d, want 2", len(wf.Jobs))
	}

	job1, exists := wf.Jobs["job1"]
	if !exists {
		t.Fatal("job1 not found in Jobs map")
	}

	if job1.Name != "Job One" {
		t.Errorf("job1.Name = %q, want %q", job1.Name, "Job One")
	}

	if job1.RunsOn != "ubuntu-latest" {
		t.Errorf("job1.RunsOn = %q, want %q", job1.RunsOn, "ubuntu-latest")
	}

	if job1.IsSelfHosted {
		t.Error("job1.IsSelfHosted = true, want false")
	}

	if len(job1.Permissions.Granular) != 2 {
		t.Fatalf("len(job1.Permissions.Granular) = %d, want 2", len(job1.Permissions.Granular))
	}

	if job1.Permissions.Granular["contents"] != "read" {
		t.Errorf("job1 contents permission = %q, want %q", job1.Permissions.Granular["contents"], "read")
	}

	if job1.Permissions.Granular["issues"] != "write" {
		t.Errorf("job1 issues permission = %q, want %q", job1.Permissions.Granular["issues"], "write")
	}

	if len(job1.Steps) != 2 {
		t.Fatalf("len(job1.Steps) = %d, want 2", len(job1.Steps))
	}

	step0 := job1.Steps[0]
	if step0.Name != "Checkout" {
		t.Errorf("step0.Name = %q, want %q", step0.Name, "Checkout")
	}
	if step0.Uses != "actions/checkout@v4" {
		t.Errorf("step0.Uses = %q, want %q", step0.Uses, "actions/checkout@v4")
	}
	if step0.Run != "" {
		t.Errorf("step0.Run = %q, want empty", step0.Run)
	}
	if step0.With["fetch-depth"] != "0" {
		t.Errorf("step0.With[fetch-depth] = %q, want %q", step0.With["fetch-depth"], "0")
	}
	if step0.Env["KEY"] != "value" {
		t.Errorf("step0.Env[KEY] = %q, want %q", step0.Env["KEY"], "value")
	}

	step1 := job1.Steps[1]
	if step1.Name != "Run build" {
		t.Errorf("step1.Name = %q, want %q", step1.Name, "Run build")
	}
	if step1.Run != "make build" {
		t.Errorf("step1.Run = %q, want %q", step1.Run, "make build")
	}
	if step1.Uses != "" {
		t.Errorf("step1.Uses = %q, want empty", step1.Uses)
	}

	job2, exists := wf.Jobs["job2"]
	if !exists {
		t.Fatal("job2 not found in Jobs map")
	}

	if job2.Name != "Job Two" {
		t.Errorf("job2.Name = %q, want %q", job2.Name, "Job Two")
	}

	if job2.RunsOn != "self-hosted, linux" {
		t.Errorf("job2.RunsOn = %q, want %q", job2.RunsOn, "self-hosted, linux")
	}

	if !job2.IsSelfHosted {
		t.Error("job2.IsSelfHosted = false, want true")
	}

	if len(job2.Steps) != 1 {
		t.Fatalf("len(job2.Steps) = %d, want 1", len(job2.Steps))
	}
}

// TestParseWorkflow_WriteAllPerms tests permissions: write-all.
func TestParseWorkflow_WriteAllPerms(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Write All Test
permissions: write-all
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	if !wf.Permissions.IsWriteAll {
		t.Error("IsWriteAll = false, want true")
	}

	if wf.Permissions.Raw != "write-all" {
		t.Errorf("Raw = %q, want %q", wf.Permissions.Raw, "write-all")
	}
}

// TestParseWorkflow_GranularPerms tests granular permissions.
func TestParseWorkflow_GranularPerms(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Granular Perms Test
permissions:
  contents: read
  issues: write
  pull-requests: admin
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	if wf.Permissions.IsWriteAll {
		t.Error("IsWriteAll = true, want false")
	}

	if len(wf.Permissions.Granular) != 3 {
		t.Fatalf("len(Granular) = %d, want 3", len(wf.Permissions.Granular))
	}

	expectedPerms := map[string]string{
		"contents":      "read",
		"issues":        "write",
		"pull-requests": "admin",
	}

	for key, expectedVal := range expectedPerms {
		if val, ok := wf.Permissions.Granular[key]; !ok || val != expectedVal {
			t.Errorf("Granular[%s] = %q, want %q", key, val, expectedVal)
		}
	}
}

// TestParseWorkflow_NilPerms tests no permissions block.
func TestParseWorkflow_NilPerms(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: No Perms Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	if wf.Permissions.IsWriteAll {
		t.Error("IsWriteAll = true, want false")
	}

	if len(wf.Permissions.Granular) != 0 {
		t.Errorf("len(Granular) = %d, want 0", len(wf.Permissions.Granular))
	}

	if wf.Permissions.Raw != "" {
		t.Errorf("Raw = %q, want empty", wf.Permissions.Raw)
	}
}

// TestParseWorkflow_SelfHosted tests runs-on: self-hosted detection.
func TestParseWorkflow_SelfHosted(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Self Hosted Test
on: push
jobs:
  test:
    runs-on: self-hosted
    steps:
      - run: echo test
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	job := wf.Jobs["test"]
	if !job.IsSelfHosted {
		t.Error("IsSelfHosted = false, want true")
	}
}

// TestParseWorkflow_RunsOnArray tests runs-on as array.
func TestParseWorkflow_RunsOnArray(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Runs On Array Test
on: push
jobs:
  test:
    runs-on:
      - self-hosted
      - linux
      - x64
    steps:
      - run: echo test
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	job := wf.Jobs["test"]
	expectedRunsOn := "self-hosted, linux, x64"
	if job.RunsOn != expectedRunsOn {
		t.Errorf("RunsOn = %q, want %q", job.RunsOn, expectedRunsOn)
	}

	if !job.IsSelfHosted {
		t.Error("IsSelfHosted = false, want true (array contains self-hosted)")
	}
}

// TestParseWorkflow_RunsOnString tests runs-on as string.
func TestParseWorkflow_RunsOnString(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Runs On String Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	job := wf.Jobs["test"]
	if job.RunsOn != "ubuntu-latest" {
		t.Errorf("RunsOn = %q, want %q", job.RunsOn, "ubuntu-latest")
	}

	if job.IsSelfHosted {
		t.Error("IsSelfHosted = true, want false")
	}
}

// TestParseWorkflow_InvalidYAML tests malformed YAML.
func TestParseWorkflow_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Invalid YAML
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
        invalid: [unclosed array
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err == nil {
		t.Fatal("ParseWorkflow() error = nil, want error")
	}

	if wf != nil {
		t.Fatal("ParseWorkflow() returned non-nil Workflow on error")
	}

	if !contains(err.Error(), "parsing workflow") {
		t.Errorf("error message = %q, should contain 'parsing workflow'", err.Error())
	}
}

// TestParseWorkflow_FileNotFound tests non-existent file.
func TestParseWorkflow_FileNotFound(t *testing.T) {
	wf, err := ParseWorkflow("/nonexistent/path/workflow.yml")
	if err == nil {
		t.Fatal("ParseWorkflow() error = nil, want error")
	}

	if wf != nil {
		t.Fatal("ParseWorkflow() returned non-nil Workflow on error")
	}

	if !contains(err.Error(), "reading workflow") {
		t.Errorf("error message = %q, should contain 'reading workflow'", err.Error())
	}
}

// TestParseAllWorkflows_YmlAndYaml tests parsing both .yml and .yaml files.
func TestParseAllWorkflows_YmlAndYaml(t *testing.T) {
	tmpDir := t.TempDir()

	yml := filepath.Join(tmpDir, "test.yml")
	ymlContent := `
name: YML Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo yml
`

	yaml := filepath.Join(tmpDir, "test.yaml")
	yamlContent := `
name: YAML Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo yaml
`

	if err := os.WriteFile(yml, []byte(ymlContent), 0644); err != nil {
		t.Fatalf("failed to write yml: %v", err)
	}

	if err := os.WriteFile(yaml, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write yaml: %v", err)
	}

	workflows, err := ParseAllWorkflows(tmpDir)
	if err != nil {
		t.Fatalf("ParseAllWorkflows() error: %v", err)
	}

	if len(workflows) != 2 {
		t.Fatalf("len(workflows) = %d, want 2", len(workflows))
	}

	names := make(map[string]bool)
	for _, wf := range workflows {
		names[wf.Name] = true
	}

	if !names["YML Workflow"] {
		t.Error("YML Workflow not found")
	}

	if !names["YAML Workflow"] {
		t.Error("YAML Workflow not found")
	}
}

// TestParseAllWorkflows_EmptyDir tests empty directory.
func TestParseAllWorkflows_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	workflows, err := ParseAllWorkflows(tmpDir)
	if err != nil {
		t.Fatalf("ParseAllWorkflows() error: %v", err)
	}

	if workflows != nil {
		t.Errorf("workflows = %v, want nil", workflows)
	}
}

// TestParseAllWorkflows_SkipsInvalid tests that invalid YAML is skipped.
func TestParseAllWorkflows_SkipsInvalid(t *testing.T) {
	tmpDir := t.TempDir()

	valid := filepath.Join(tmpDir, "valid.yml")
	validContent := `
name: Valid Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo valid
`

	invalid := filepath.Join(tmpDir, "invalid.yml")
	invalidContent := `
name: Invalid Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo invalid
        bad: [unclosed
`

	if err := os.WriteFile(valid, []byte(validContent), 0644); err != nil {
		t.Fatalf("failed to write valid: %v", err)
	}

	if err := os.WriteFile(invalid, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("failed to write invalid: %v", err)
	}

	workflows, err := ParseAllWorkflows(tmpDir)
	if err != nil {
		t.Fatalf("ParseAllWorkflows() error: %v", err)
	}

	if len(workflows) != 1 {
		t.Fatalf("len(workflows) = %d, want 1 (invalid skipped)", len(workflows))
	}

	if workflows[0].Name != "Valid Workflow" {
		t.Errorf("workflow name = %q, want %q", workflows[0].Name, "Valid Workflow")
	}
}

// TestParseActionRef_Standard tests "owner/repo@version".
func TestParseActionRef_Standard(t *testing.T) {
	ref := ParseActionRef("actions/checkout@v4")
	if ref == nil {
		t.Fatal("ParseActionRef() returned nil")
	}

	if ref.Owner != "actions" {
		t.Errorf("Owner = %q, want %q", ref.Owner, "actions")
	}

	if ref.Repo != "checkout" {
		t.Errorf("Repo = %q, want %q", ref.Repo, "checkout")
	}

	if ref.Version != "v4" {
		t.Errorf("Version = %q, want %q", ref.Version, "v4")
	}

	if ref.IsPinned {
		t.Error("IsPinned = true, want false")
	}

	if ref.IsLocal {
		t.Error("IsLocal = true, want false")
	}
}

// TestParseActionRef_Pinned40 tests SHA-40 pinning.
func TestParseActionRef_Pinned40(t *testing.T) {
	sha40 := "0123456789abcdef0123456789abcdef01234567"
	ref := ParseActionRef(fmt.Sprintf("owner/repo@%s", sha40))
	if ref == nil {
		t.Fatal("ParseActionRef() returned nil")
	}

	if ref.Owner != "owner" {
		t.Errorf("Owner = %q, want %q", ref.Owner, "owner")
	}

	if ref.Repo != "repo" {
		t.Errorf("Repo = %q, want %q", ref.Repo, "repo")
	}

	if ref.Version != sha40 {
		t.Errorf("Version = %q, want %q", ref.Version, sha40)
	}

	if !ref.IsPinned {
		t.Error("IsPinned = false, want true")
	}
}

// TestParseActionRef_Pinned64 tests SHA-64 pinning.
func TestParseActionRef_Pinned64(t *testing.T) {
	sha64 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ref := ParseActionRef(fmt.Sprintf("owner/repo@%s", sha64))
	if ref == nil {
		t.Fatal("ParseActionRef() returned nil")
	}

	if ref.Owner != "owner" {
		t.Errorf("Owner = %q, want %q", ref.Owner, "owner")
	}

	if ref.Repo != "repo" {
		t.Errorf("Repo = %q, want %q", ref.Repo, "repo")
	}

	if !ref.IsPinned {
		t.Error("IsPinned = false, want true")
	}
}

// TestParseActionRef_Local tests "./" prefix for local actions.
func TestParseActionRef_Local(t *testing.T) {
	ref := ParseActionRef("./my-action")
	if ref == nil {
		t.Fatal("ParseActionRef() returned nil")
	}

	if !ref.IsLocal {
		t.Error("IsLocal = false, want true")
	}
}

// TestParseActionRef_LocalParent tests "../" prefix for parent local actions.
func TestParseActionRef_LocalParent(t *testing.T) {
	ref := ParseActionRef("../shared-action")
	if ref == nil {
		t.Fatal("ParseActionRef() returned nil")
	}

	if !ref.IsLocal {
		t.Error("IsLocal = false, want true")
	}
}

// TestParseActionRef_Docker tests "docker://" prefix.
func TestParseActionRef_Docker(t *testing.T) {
	ref := ParseActionRef("docker://alpine:3.8")
	if ref == nil {
		t.Fatal("ParseActionRef() returned nil")
	}

	if ref.Owner != "docker" {
		t.Errorf("Owner = %q, want %q", ref.Owner, "docker")
	}

	if !contains(ref.Repo, "docker://") {
		t.Errorf("Repo = %q, should contain 'docker://'", ref.Repo)
	}
}

// TestParseActionRef_Empty tests empty string.
func TestParseActionRef_Empty(t *testing.T) {
	ref := ParseActionRef("")
	if ref != nil {
		t.Errorf("ParseActionRef(\"\") = %v, want nil", ref)
	}
}

// TestParseActionRef_NoAt tests no @ separator.
func TestParseActionRef_NoAt(t *testing.T) {
	ref := ParseActionRef("owner/repo")
	if ref != nil {
		t.Errorf("ParseActionRef() = %v, want nil (no @ separator)", ref)
	}
}

// TestParseActionRef_SubPath tests owner/repo/subpath@version.
func TestParseActionRef_SubPath(t *testing.T) {
	ref := ParseActionRef("owner/repo/subpath@v1")
	if ref == nil {
		t.Fatal("ParseActionRef() returned nil")
	}

	if ref.Owner != "owner" {
		t.Errorf("Owner = %q, want %q", ref.Owner, "owner")
	}

	if ref.Repo != "repo" {
		t.Errorf("Repo = %q, want %q", ref.Repo, "repo")
	}

	if ref.Version != "v1" {
		t.Errorf("Version = %q, want %q", ref.Version, "v1")
	}
}

// TestIsOfficialAction_Trusted tests trusted org owners.
func TestIsOfficialAction_Trusted(t *testing.T) {
	trustedOrgs := []string{
		"actions",
		"github",
		"docker",
		"azure",
		"aws-actions",
		"google-github-actions",
		"hashicorp",
		"goreleaser",
		"codecov",
	}

	for _, org := range trustedOrgs {
		ref := &ActionRef{Owner: org, Repo: "test"}
		if !IsOfficialAction(ref) {
			t.Errorf("IsOfficialAction(%s) = false, want true", org)
		}
	}
}

// TestIsOfficialAction_ThirdParty tests third-party owner.
func TestIsOfficialAction_ThirdParty(t *testing.T) {
	ref := &ActionRef{Owner: "random-user", Repo: "random-action"}
	if IsOfficialAction(ref) {
		t.Error("IsOfficialAction(random-user) = true, want false")
	}
}

// TestIsOfficialAction_Local tests local action is trusted.
func TestIsOfficialAction_Local(t *testing.T) {
	ref := &ActionRef{IsLocal: true}
	if !IsOfficialAction(ref) {
		t.Error("IsOfficialAction(local) = false, want true")
	}
}

// TestIsOfficialAction_Nil tests nil ActionRef is trusted.
func TestIsOfficialAction_Nil(t *testing.T) {
	if !IsOfficialAction(nil) {
		t.Error("IsOfficialAction(nil) = false, want true")
	}
}

// TestParseWorkflow_MultipleJobs tests multiple jobs with different configs.
func TestParseWorkflow_MultipleJobs(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Multi Job Test
on: push
jobs:
  job-a:
    name: Job A
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  job-b:
    name: Job B
    runs-on: macos-latest
    steps:
      - run: echo test
  job-c:
    name: Job C
    runs-on: windows-latest
    steps: []
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	if len(wf.Jobs) != 3 {
		t.Fatalf("len(Jobs) = %d, want 3", len(wf.Jobs))
	}

	for jobID, job := range wf.Jobs {
		if job.RunsOn == "" {
			t.Errorf("job %s has empty RunsOn", jobID)
		}
	}

	// Verify specific jobs
	if wf.Jobs["job-a"].Name != "Job A" {
		t.Errorf("job-a.Name = %q, want %q", wf.Jobs["job-a"].Name, "Job A")
	}

	if wf.Jobs["job-b"].RunsOn != "macos-latest" {
		t.Errorf("job-b.RunsOn = %q, want %q", wf.Jobs["job-b"].RunsOn, "macos-latest")
	}

	if wf.Jobs["job-c"].RunsOn != "windows-latest" {
		t.Errorf("job-c.RunsOn = %q, want %q", wf.Jobs["job-c"].RunsOn, "windows-latest")
	}
}

// TestParseWorkflow_ReadAllPerms tests "read-all" permissions.
func TestParseWorkflow_ReadAllPerms(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Read All Test
permissions: read-all
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo test
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	if wf.Permissions.IsWriteAll {
		t.Error("IsWriteAll = true for read-all, want false")
	}

	if wf.Permissions.Raw != "read-all" {
		t.Errorf("Raw = %q, want %q", wf.Permissions.Raw, "read-all")
	}
}

// TestParseWorkflow_JobPermissions tests job-level permissions override.
func TestParseWorkflow_JobPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Job Perms Test
permissions: read-all
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo test
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	// Workflow-level: read-all
	if wf.Permissions.IsWriteAll {
		t.Error("wf.Permissions.IsWriteAll = true for read-all, want false")
	}

	// Job-level: write-all
	job := wf.Jobs["test"]
	if !job.Permissions.IsWriteAll {
		t.Error("job.Permissions.IsWriteAll = false for write-all, want true")
	}
}

// TestParseWorkflow_EmptyRunsOn tests runs-on with no value.
func TestParseWorkflow_EmptyRunsOn(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Empty RunsOn Test
on: push
jobs:
  test:
    steps:
      - run: echo test
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	job := wf.Jobs["test"]
	if job.RunsOn != "" {
		t.Errorf("RunsOn = %q, want empty", job.RunsOn)
	}

	if job.IsSelfHosted {
		t.Error("IsSelfHosted = true for empty RunsOn, want false")
	}
}

// TestParseWorkflow_StepsWithoutUsesOrRun tests steps missing both uses and run.
func TestParseWorkflow_StepsWithoutUsesOrRun(t *testing.T) {
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "workflow.yml")

	workflowContent := `
name: Step Without Uses Or Run
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: No Uses Or Run
        with:
          key: value
`

	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to write workflow: %v", err)
	}

	wf, err := ParseWorkflow(workflowPath)
	if err != nil {
		t.Fatalf("ParseWorkflow() error: %v", err)
	}

	job := wf.Jobs["test"]
	if len(job.Steps) != 1 {
		t.Fatalf("len(Steps) = %d, want 1", len(job.Steps))
	}

	step := job.Steps[0]
	if step.Name != "No Uses Or Run" {
		t.Errorf("Step.Name = %q, want %q", step.Name, "No Uses Or Run")
	}

	if step.Uses != "" {
		t.Errorf("Step.Uses = %q, want empty", step.Uses)
	}

	if step.Run != "" {
		t.Errorf("Step.Run = %q, want empty", step.Run)
	}

	if step.With["key"] != "value" {
		t.Errorf("Step.With[key] = %q, want %q", step.With["key"], "value")
	}
}

// TestParseActionRef_BadSHA tests non-hex characters in SHA version.
func TestParseActionRef_BadSHA(t *testing.T) {
	// 40 chars but not valid hex (contains 'z')
	badSHA40 := "0123456789abcdef0123456789abcdef0123456z"
	ref := ParseActionRef(fmt.Sprintf("owner/repo@%s", badSHA40))
	if ref == nil {
		t.Fatal("ParseActionRef() returned nil")
	}

	if ref.IsPinned {
		t.Error("IsPinned = true for non-hex string, want false")
	}

	if ref.Version != badSHA40 {
		t.Errorf("Version = %q, want %q", ref.Version, badSHA40)
	}
}

// TestParseActionRef_WrongSHALength tests SHA with wrong length.
func TestParseActionRef_WrongSHALength(t *testing.T) {
	// 39 chars (not 40 or 64)
	wrongLen := "0123456789abcdef0123456789abcdef012345"
	ref := ParseActionRef(fmt.Sprintf("owner/repo@%s", wrongLen))
	if ref == nil {
		t.Fatal("ParseActionRef() returned nil")
	}

	if ref.IsPinned {
		t.Error("IsPinned = true for wrong length SHA, want false")
	}
}

// TestParseActionRef_MultipleAtSigns tests action ref with multiple @ signs.
func TestParseActionRef_MultipleAtSigns(t *testing.T) {
	// Uses the LAST @ sign as separator
	ref := ParseActionRef("owner/repo@v1@extra")
	if ref == nil {
		t.Fatal("ParseActionRef() returned nil")
	}

	if ref.Version != "extra" {
		t.Errorf("Version = %q (should use last @), want %q", ref.Version, "extra")
	}
}

// TestIsOfficialAction_Table tests a table of org names.
func TestIsOfficialAction_Table(t *testing.T) {
	tests := []struct {
		name     string
		owner    string
		wantTrue bool
	}{
		{"actions org", "actions", true},
		{"github org", "github", true},
		{"docker org", "docker", true},
		{"azure org", "azure", true},
		{"aws-actions org", "aws-actions", true},
		{"google-github-actions org", "google-github-actions", true},
		{"hashicorp org", "hashicorp", true},
		{"goreleaser org", "goreleaser", true},
		{"codecov org", "codecov", true},
		{"random user", "random-user", false},
		{"unknown org", "some-org", false},
		{"empty owner", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := &ActionRef{Owner: tt.owner, Repo: "test"}
			result := IsOfficialAction(ref)
			if result != tt.wantTrue {
				t.Errorf("IsOfficialAction(%q) = %v, want %v", tt.owner, result, tt.wantTrue)
			}
		})
	}
}

// contains is a helper to check if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr)))
}

// containsSubstring checks if s contains substr as a substring.
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

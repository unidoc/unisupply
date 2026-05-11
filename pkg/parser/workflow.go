// Package parser — workflow.go handles GitHub Actions workflow parsing.
package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow represents a parsed GitHub Actions workflow file.
type Workflow struct {
	Name        string
	FilePath    string
	Permissions WorkflowPermissions
	Jobs        map[string]*WorkflowJob
}

// WorkflowPermissions represents the permissions block.
type WorkflowPermissions struct {
	Raw        string            // e.g., "write-all", "read-all"
	Granular   map[string]string // e.g., {"contents": "read", "issues": "write"}
	IsWriteAll bool
}

// WorkflowJob represents a job in a workflow.
type WorkflowJob struct {
	Name         string
	RunsOn       string
	Permissions  WorkflowPermissions
	Steps        []WorkflowStep
	IsSelfHosted bool
}

// WorkflowStep represents a step in a job.
type WorkflowStep struct {
	Name string
	Uses string // action reference, e.g., "actions/checkout@v4"
	Run  string // shell command
	With map[string]string
	Env  map[string]string
}

// ActionRef represents a parsed action reference.
type ActionRef struct {
	Owner    string
	Repo     string
	Version  string
	IsPinned bool // true if version is a full SHA
	IsLocal  bool // true if it's a local action (e.g., ./.github/actions/foo)
}

// rawWorkflow is the raw YAML structure for unmarshaling.
type rawWorkflow struct {
	Name        string            `yaml:"name"`
	Permissions interface{}       `yaml:"permissions"`
	On          interface{}       `yaml:"on"`
	Jobs        map[string]rawJob `yaml:"jobs"`
}

type rawJob struct {
	Name        string      `yaml:"name"`
	RunsOn      interface{} `yaml:"runs-on"`
	Permissions interface{} `yaml:"permissions"`
	Steps       []rawStep   `yaml:"steps"`
}

type rawStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]string `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

// ParseWorkflow parses a single GitHub Actions workflow YAML file.
func ParseWorkflow(path string) (*Workflow, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- caller-supplied workflow file path is the parser's input contract
	if err != nil {
		return nil, fmt.Errorf("reading workflow %s: %w", path, err)
	}

	var raw rawWorkflow
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing workflow %s: %w", path, err)
	}

	wf := &Workflow{
		Name:        raw.Name,
		FilePath:    path,
		Permissions: parsePermissions(raw.Permissions),
		Jobs:        make(map[string]*WorkflowJob),
	}

	for jobID, rawJob := range raw.Jobs {
		job := &WorkflowJob{
			Name:        rawJob.Name,
			RunsOn:      parseRunsOn(rawJob.RunsOn),
			Permissions: parsePermissions(rawJob.Permissions),
		}

		job.IsSelfHosted = strings.Contains(strings.ToLower(job.RunsOn), "self-hosted")

		for _, rs := range rawJob.Steps {
			step := WorkflowStep{
				Name: rs.Name,
				Uses: rs.Uses,
				Run:  rs.Run,
				With: rs.With,
				Env:  rs.Env,
			}
			job.Steps = append(job.Steps, step)
		}

		wf.Jobs[jobID] = job
	}

	return wf, nil
}

// ParseAllWorkflows parses all workflow files in a directory.
func ParseAllWorkflows(dir string) ([]*Workflow, error) {
	pattern := filepath.Join(dir, "*.yml")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("globbing workflows: %w", err)
	}

	// Also check .yaml extension.
	yamlFiles, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err == nil {
		files = append(files, yamlFiles...)
	}

	if len(files) == 0 {
		return nil, nil
	}

	var workflows []*Workflow
	for _, f := range files {
		wf, err := ParseWorkflow(f)
		if err != nil {
			// Skip unparseable files with a warning.
			continue
		}
		workflows = append(workflows, wf)
	}

	return workflows, nil
}

// ParseActionRef parses an action reference string into its components.
func ParseActionRef(uses string) *ActionRef {
	if uses == "" {
		return nil
	}

	// Local actions.
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "../") {
		return &ActionRef{IsLocal: true}
	}

	// Docker actions.
	if strings.HasPrefix(uses, "docker://") {
		return &ActionRef{Owner: "docker", Repo: uses, Version: "latest"}
	}

	// Standard format: owner/repo@version or owner/repo/path@version.
	atIdx := strings.LastIndex(uses, "@")
	if atIdx < 0 {
		return nil
	}

	ref := uses[:atIdx]
	version := uses[atIdx+1:]

	parts := strings.SplitN(ref, "/", 3)
	if len(parts) < 2 {
		return nil
	}

	sha40Regex := regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha64Regex := regexp.MustCompile(`^[0-9a-f]{64}$`)

	return &ActionRef{
		Owner:    parts[0],
		Repo:     parts[1],
		Version:  version,
		IsPinned: sha40Regex.MatchString(version) || sha64Regex.MatchString(version),
	}
}

// IsOfficialAction returns true if the action is from a trusted GitHub org.
func IsOfficialAction(ref *ActionRef) bool {
	if ref == nil || ref.IsLocal {
		return true
	}

	trustedOrgs := map[string]bool{
		"actions":               true,
		"github":                true,
		"docker":                true,
		"azure":                 true,
		"aws-actions":           true,
		"google-github-actions": true,
		"hashicorp":             true,
		"goreleaser":            true,
		"codecov":               true,
	}

	return trustedOrgs[ref.Owner]
}

func parsePermissions(raw interface{}) WorkflowPermissions {
	if raw == nil {
		return WorkflowPermissions{}
	}

	switch v := raw.(type) {
	case string:
		return WorkflowPermissions{
			Raw:        v,
			IsWriteAll: v == "write-all",
		}
	case map[string]interface{}:
		granular := make(map[string]string)
		for key, val := range v {
			if s, ok := val.(string); ok {
				granular[key] = s
			}
		}
		return WorkflowPermissions{
			Granular: granular,
		}
	}

	return WorkflowPermissions{}
}

func parseRunsOn(raw interface{}) string {
	if raw == nil {
		return ""
	}

	switch v := raw.(type) {
	case string:
		return v
	case []interface{}:
		var parts []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	}

	return fmt.Sprintf("%v", raw)
}

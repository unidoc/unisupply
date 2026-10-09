package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// goVersionEnvPrefix is the environment entry govulncheck reads to override the
// Go version it matches standard-library vulnerabilities against.
const goVersionEnvPrefix = "GOVERSION="

// resolveGoEnv returns the Go version and GOROOT that the go command resolves
// when run in dir. An empty dir uses the process working directory, which is
// where govulncheck resolves its own values, so comparing the two results
// shows whether the project and the scanner use different toolchains.
func resolveGoEnv(ctx context.Context, dir string) (goVersion, goRoot string, err error) {
	cmd := exec.CommandContext(ctx, "go", "env", "-json", "GOVERSION", "GOROOT")
	cmd.Dir = dir

	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("go env: %w", err)
	}

	var env struct {
		GoVersion string `json:"GOVERSION"`
		GoRoot    string `json:"GOROOT"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		return "", "", fmt.Errorf("decoding go env output: %w", err)
	}
	if env.GoVersion == "" || env.GoRoot == "" {
		return "", "", fmt.Errorf("go env returned an empty GOVERSION (%q) or GOROOT (%q)", env.GoVersion, env.GoRoot)
	}
	return env.GoVersion, env.GoRoot, nil
}

// govulncheckEnv returns the environment for the in-process govulncheck run:
// a copy of base with GOVERSION set to goVersion. govulncheck reads GOVERSION
// from this environment before it would exec `go env` in the process working
// directory, so setting it makes standard-library matching follow the project's
// toolchain. base is returned unchanged (as a copy) when goVersion is empty or
// when base already sets GOVERSION: an explicit setting by the user wins, and
// govulncheck takes the last match, so appending would silently override it.
func govulncheckEnv(base []string, goVersion string) []string {
	env := make([]string, len(base), len(base)+1)
	copy(env, base)

	if goVersion == "" {
		return env
	}
	for _, e := range base {
		if strings.HasPrefix(e, goVersionEnvPrefix) {
			return env
		}
	}
	return append(env, goVersionEnvPrefix+goVersion)
}

// rebaseStdlibFile re-expresses a standard-library frame filename relative to
// the project's GOROOT. govulncheck makes stdlib filenames relative to the
// GOROOT of the process it runs in (scannerGOROOT), while the package sources
// come from the project's toolchain (projectGOROOT); when the two differ the
// filename climbs out with "../". The result is a path inside the project's
// GOROOT such as "src/sync/once.go". filename is returned unchanged when it is
// empty, either root is empty, the roots are the same, or the rebased path
// would still leave the project's GOROOT, so that the caller's drop rule
// applies to it.
func rebaseStdlibFile(filename, scannerGOROOT, projectGOROOT string) string {
	if filename == "" || scannerGOROOT == "" || projectGOROOT == "" {
		return filename
	}
	if filepath.Clean(scannerGOROOT) == filepath.Clean(projectGOROOT) {
		return filename
	}

	abs := filepath.Join(scannerGOROOT, filepath.FromSlash(filename))
	rel, err := filepath.Rel(projectGOROOT, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filename
	}
	return filepath.ToSlash(rel)
}

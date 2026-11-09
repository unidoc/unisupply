//go:build !linux && !darwin

package scanner

import "time"

// stopChildProcesses does nothing here: on these systems a `go list` that govulncheck started can outlive a scan that was
// cancelled while it ran (on Windows the go command does not run it in a group of its own, and the child is killed).
func stopChildProcesses(time.Duration) {}

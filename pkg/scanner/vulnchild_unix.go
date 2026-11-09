//go:build linux || darwin

package scanner

import (
	"os"
	"syscall"
	"time"
)

// childProc is a live process that this process started.
type childProc struct {
	pid, pgid int
}

// stopChildProcesses stops the processes this process started (govulncheck's `go list`, and `go env`/`go version`):
// SIGINT, so that the go command can clean up, then SIGKILL to those still there after grace. The go command runs
// each of them as the leader of a process group of its own (golang.org/x/tools/internal/gocommand), so the signal goes
// to the group, which reaches the compilers and cgo processes they started too.
func stopChildProcesses(grace time.Duration) {
	signalChildProcesses(syscall.SIGINT)
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if len(liveChildProcesses()) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	signalChildProcesses(syscall.SIGKILL)
}

func signalChildProcesses(sig syscall.Signal) {
	for _, c := range liveChildProcesses() {
		if c.pgid == c.pid {
			_ = syscall.Kill(-c.pid, sig)
		} else {
			_ = syscall.Kill(c.pid, sig)
		}
	}
}

// liveChildProcesses lists the processes whose parent is this process, without those that have exited and wait to be
// reaped. An error listing them gives none: stopping them is the best this process can do on its way out.
func liveChildProcesses() []childProc {
	procs, _ := listChildProcesses(os.Getpid())
	return procs
}

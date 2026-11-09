//go:build linux || darwin

package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// fakeChildPidsEnv names the file where the "golist" fake writes its own pid and the pid of the process it started.
const fakeChildPidsEnv = "UNISUPPLY_TEST_FAKE_CHILD_PIDS"

// fakeGoList starts a long-running process the way golang.org/x/tools' gocommand starts `go list` (the leader of a
// process group of its own, no context: x/vuln v1.9.0 gives the loader none), writes "<own pid> <its pid>" to the file
// fakeChildPidsEnv names, and blocks.
func fakeGoList() error {
	cmd := exec.Command("sleep", "3600")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // gocommand waits for it too: it is reaped as soon as it ends
	path := os.Getenv(fakeChildPidsEnv)
	if err := os.WriteFile(path+".tmp", fmt.Appendf(nil, "%d %d", os.Getpid(), cmd.Process.Pid), 0o600); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	time.Sleep(time.Hour)
	return nil
}

// readFakePids waits for the "golist" fake to write its pids.
func readFakePids(t *testing.T, path string) (child, goList int) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if _, err := fmt.Sscan(string(b), &child, &goList); err != nil {
			t.Fatalf("pids file %q: %v", b, err)
		}
		t.Cleanup(func() { _ = syscall.Kill(-goList, syscall.SIGKILL) })
		return child, goList
	}
	t.Fatal("the golist fake did not start its process")
	return 0, 0
}

// waitGone fails unless the process ends within a few seconds. A zombie has ended: once the child exits, the process
// it started is reaped by whatever adopts it, and in a container where the test binary is pid 1 that never happens.
func waitGone(t *testing.T, pid int, what string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if processZombie(pid) {
			t.Logf("%s (pid %d) has ended and waits to be reaped", what, pid)
			return
		}
	}
	t.Errorf("%s (pid %d) is still running", what, pid)
}

// startGoListPass runs a pass whose child runs the "golist" fake, and returns the pids once the fake's process runs.
func startGoListPass(t *testing.T, ctx context.Context) (child, goList int, done <-chan error) {
	t.Helper()
	pids := filepath.Join(t.TempDir(), "pids")
	r := &govulncheckRun{projectDir: t.TempDir(), env: append(os.Environ(), fakeChildEnv+"=golist", fakeChildPidsEnv+"="+pids)}
	ch := make(chan error, 1)
	go func() {
		_, _, _, err := r.pass(ctx, scanLevelPackage, nil)
		ch <- err
	}()
	child, goList = readFakePids(t, pids)
	return child, goList, ch
}

func TestChild_CancelStopsTheGoListItStarted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, goList, done := startGoListPass(t, ctx)
	cancel()
	select {
	case err := <-done:
		sameClass(t, asScanError(t, err), context.Canceled.Error(), context.Canceled)
	case <-time.After(childWaitDelay + 5*time.Second):
		t.Fatal("the scan did not return after the cancel")
	}
	waitGone(t, goList, "the go list the child started")
}

func TestChild_ParentGoneStopsTheGoListItStarted(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinW.Close()
	pids := filepath.Join(t.TempDir(), "pids")
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), vulnChildEnv+"=1", fakeChildEnv+"=golist", fakeChildPidsEnv+"="+pids)
	cmd.Stdin = stdinR
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stdinR.Close()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	_, goList := readFakePids(t, pids)

	stdinW.Close() // the parent is gone
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != childStoppedStatus {
			t.Errorf("child ended with %v, want exit status %d", err, childStoppedStatus)
		}
	case <-time.After(childWaitDelay + 5*time.Second):
		t.Fatal("the child kept running after its stdin closed")
	}
	waitGone(t, goList, "the go list the child started")
}

func TestChild_GoListDoesNotInheritAnIgnoredSIGINT(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, goList, done := startGoListPass(t, ctx)
	// The SIGINT that the go command's own cancel sends, or a stop below: an ignored disposition would be inherited.
	if err := syscall.Kill(goList, syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	waitGone(t, goList, "the go list after SIGINT")
	cancel()
	<-done
}

func TestChild_ExternalSIGTERMDoesNotStopTheScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	child, goList, done := startGoListPass(t, ctx)
	// A service manager that stops the whole group: the host decides, through its context, whether the scan stops.
	if err := syscall.Kill(child, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("the scan ended on a SIGTERM that its context did not send: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := syscall.Kill(goList, 0); err != nil {
		t.Fatalf("the go list stopped on a SIGTERM to the child: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		sameClass(t, asScanError(t, err), context.Canceled.Error(), context.Canceled)
	case <-time.After(childWaitDelay + 5*time.Second):
		t.Fatal("the scan did not return after the cancel")
	}
	waitGone(t, goList, "the go list the child started")
}

func TestChild_HangupDoesNotLeaveTheGoListBehind(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinW.Close()
	pids := filepath.Join(t.TempDir(), "pids")
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), vulnChildEnv+"=1", fakeChildEnv+"=golist", fakeChildPidsEnv+"="+pids)
	cmd.Stdin = stdinR
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stdinR.Close()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	_, goList := readFakePids(t, pids)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	// A terminal that hangs up sends SIGHUP to its foreground process group, the host and the child; the host goes away.
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	stdinW.Close()
	select {
	case <-done:
	case <-time.After(childWaitDelay + 5*time.Second):
		t.Fatal("the child kept running after its stdin closed")
	}
	waitGone(t, goList, "the go list the child started")
}

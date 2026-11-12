package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/netlog"
)

// fakeChildEnv names the fake that a test binary started as the govulncheck child runs in place of govulncheck (see
// TestMain). The child is the real test binary started again, so every test here exercises a real process.
const fakeChildEnv = "UNISUPPLY_TEST_FAKE_CHILD"

// fakeChildURLEnv carries the URL that the "http" fake requests.
const fakeChildURLEnv = "UNISUPPLY_TEST_FAKE_CHILD_URL"

// A govulncheck error text that scanFailureRules classify: the same text must give the same result in a child and in
// this process.
const childMultipleMains = "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n/x/b.go:3:6: main redeclared in this block\n\t/x/a.go:3:6: other declaration of main"

// fakeChildBody is what the child runs instead of govulncheck in the given mode. Like golang.org/x/vuln v1.9.0's package
// loader, the blocking fakes do not watch ctx.
func fakeChildBody(mode string) func(context.Context, []string) error {
	return func(ctx context.Context, _ []string) error {
		switch mode {
		case "block":
			time.Sleep(time.Hour)
		case "stubborn":
			// a child that does not stop when asked (TestMain makes its stop hang): only the kill after childWaitDelay
			// ends it
			time.Sleep(time.Hour)
		case "golist":
			// a process started the way the go command starts `go list`: in a process group of its own, with no context
			return fakeGoList()
		case "paniconcancel":
			// golang.org/x/vuln's nil dereference when the call graph build is cancelled (#174)
			<-ctx.Done()
			go func() { panic("runtime error: invalid memory address or nil pointer dereference") }()
			time.Sleep(time.Hour)
		case "noisyerror":
			// what an init function of the host could write: text that the failure rules match
			fmt.Fprintln(os.Stderr, "dial tcp: connection refused, 429 too many requests, vuln.go.dev")
			return errors.New(childMultipleMains)
		case "exit1":
			// a log.Fatal in an init function of the host, or a TerminateProcess on Windows: status 1 and no error line
			fmt.Fprintln(os.Stderr, "init: config not found")
			os.Exit(1)
		case "panic":
			go func() { panic("boom") }()
			time.Sleep(time.Hour)
		case "panicrule":
			// the dump says things that scanFailureRules match (a network fault, a rate limit)
			go func() { panic("dial tcp: connection refused, 429 too many requests, vuln.go.dev") }()
			time.Sleep(time.Hour)
		case "error":
			return errors.New(childMultipleMains)
		case "http":
			// a request to the URL the test serves: with the netlog marker it is logged to stderr as a NET line
			resp, err := http.Get(os.Getenv(fakeChildURLEnv))
			if err == nil {
				resp.Body.Close()
			}
			return errors.New("govulncheck: no packages matched the provided patterns")
		case "netlogstate":
			return fmt.Errorf("govulncheck: no packages matched the provided patterns (netlog=%v marker=%q)", netlog.Enabled(), os.Getenv(vulnChildNetlogEnv))
		case "net":
			fmt.Fprintln(os.Stderr, "NET GET vuln.go.dev /index/db.json.gz 200 12ms")
			return errors.New("govulncheck: no packages matched the provided patterns")
		}
		return fmt.Errorf("unknown fake child mode %q", mode)
	}
}

// passWithChild runs one govulncheck pass in a child that runs the given fake, counting the calls to releaseMemory.
// It drives pass directly: ScanVulnsWithOptions first runs `go env` in the project, and a cancel that lands there never
// reaches the child.
func passWithChild(t *testing.T, ctx context.Context, mode string) (warnings []string, err error, freed int) {
	t.Helper()
	if !vulnChildCapable.Load() {
		t.Fatal("TestMain must have called RunVulnChildIfRequested, so that scans run in a child process")
	}
	prev := releaseMemory
	releaseMemory = func() { freed++ }
	t.Cleanup(func() { releaseMemory = prev })
	r := &govulncheckRun{projectDir: t.TempDir(), env: append(os.Environ(), fakeChildEnv+"="+mode)}
	_, warnings, scanned, err := r.pass(ctx, scanLevelSymbol, nil)
	if scanned {
		t.Fatal("a failed child must not be a finished scan")
	}
	return warnings, err, freed
}

// passWithEnv is passWithChild with more environment for the child.
func passWithEnv(t *testing.T, mode string, extra ...string) ([]string, error) {
	t.Helper()
	r := &govulncheckRun{projectDir: t.TempDir(), env: append(append(os.Environ(), fakeChildEnv+"="+mode), extra...)}
	_, warnings, _, err := r.pass(context.Background(), scanLevelPackage, nil)
	return warnings, err
}

func asScanError(t *testing.T, err error) *ScanError {
	t.Helper()
	var se *ScanError
	if !errors.As(err, &se) {
		t.Fatalf("want a *ScanError, got %T: %v", err, err)
	}
	return se
}

// sameClass fails unless got classifies like the in-process scan would for the context error and message.
func sameClass(t *testing.T, got *ScanError, msg string, ctxErr error) {
	t.Helper()
	want := classifyScanFailure(msg, ctxErr)
	if got.Kind != want.Kind || got.Reason != want.Reason {
		t.Errorf("Kind/Reason = %v/%s, want %v/%s (what the in-process scan gives)", got.Kind, got.Reason, want.Kind, want.Reason)
	}
	if got.Summary() != want.Summary() {
		t.Errorf("Summary = %q, want %q", got.Summary(), want.Summary())
	}
}

func TestChild_CancelledScanIsTypedAndTheHostSurvives(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	defer cancel()
	start := time.Now()
	warnings, err, freed := passWithChild(t, ctx, "block")
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("the scan took %v to return after the cancel, want a bounded time", d)
	}
	se := asScanError(t, err)
	sameClass(t, se, context.Canceled.Error(), context.Canceled)
	if len(warnings) == 0 || warnings[0] != context.Canceled.Error() {
		t.Errorf("warnings = %q, want the in-process one (%q) first", warnings, context.Canceled.Error())
	}
	if freed != 0 {
		t.Errorf("releaseMemory ran %d times for a child process, want 0", freed)
	}
}

func TestChild_DeadlineIsScanDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	warnings, err, _ := passWithChild(t, ctx, "block")
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("the scan took %v to return after the deadline, want a bounded time", d)
	}
	se := asScanError(t, err)
	sameClass(t, se, context.DeadlineExceeded.Error(), context.DeadlineExceeded)
	if se.Reason != ReasonScanDeadline || se.Kind != FailTooLarge {
		t.Errorf("Kind/Reason = %v/%s, want too_large/scan_deadline", se.Kind, se.Reason)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("errors.Is(err, context.DeadlineExceeded) must hold: %v", err)
	}
	if len(warnings) == 0 || warnings[0] != context.DeadlineExceeded.Error() {
		t.Errorf("warnings = %q, want the in-process one first", warnings)
	}
}

func TestChild_ContextDoneBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err, _ := passWithChild(t, ctx, "block")
	sameClass(t, asScanError(t, err), context.Canceled.Error(), context.Canceled)
}

func TestChild_PanicIsInternalPanic(t *testing.T) {
	for _, mode := range []string{"panic", "panicrule"} {
		t.Run(mode, func(t *testing.T) {
			warnings, err, _ := passWithChild(t, context.Background(), mode)
			se := asScanError(t, err)
			if se.Reason != ReasonInternalPanic || se.Kind != FailPermanent {
				t.Fatalf("Kind/Reason = %v/%s, want permanent/internal_panic (the dump must not reach the failure rules)", se.Kind, se.Reason)
			}
			if len(warnings) == 0 {
				t.Fatal("no warning")
			}
			w := warnings[0]
			if !strings.Contains(w, "exit status 2") || !strings.Contains(w, "panic: ") || strings.Contains(w, "\n") || strings.Contains(w, "goroutine") {
				t.Errorf("warning = %q, want one line with the exit status and the panic line", w)
			}
			if mode == "panic" {
				if !strings.Contains(w, "panic: boom") {
					t.Errorf("warning = %q, want panic: boom", w)
				}
				want := "internal_panic: govulncheck child process crashed (exit status 2): panic: boom"
				if got := se.Summary(); got != want {
					t.Errorf("Summary = %q, want %q", got, want)
				}
			}
			if !strings.Contains(se.Error(), "goroutine") {
				t.Errorf("the stderr tail should stay in the error: %q", se.Error())
			}
		})
	}
}

func TestChild_ErrorClassifiesLikeInProcess(t *testing.T) {
	warnings, err, _ := passWithChild(t, context.Background(), "error")
	se := asScanError(t, err)
	sameClass(t, se, childMultipleMains, nil)
	if se.Reason != ReasonMultipleMains {
		t.Errorf("Reason = %s, want multiple_mains", se.Reason)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "main redeclared in this block") {
		t.Errorf("warnings = %q", warnings)
	}
}

func TestChild_NetLinesGoToTheHookNotTheError(t *testing.T) {
	var mu sync.Mutex
	var got []string
	prev := vulnChildNetHook
	vulnChildNetHook = func(line string) { mu.Lock(); got = append(got, line); mu.Unlock() }
	t.Cleanup(func() { vulnChildNetHook = prev })

	warnings, err, _ := passWithChild(t, context.Background(), "net")
	se := asScanError(t, err)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || !strings.HasPrefix(got[0], "NET GET vuln.go.dev") {
		t.Errorf("hook got %q, want the NET line", got)
	}
	for _, text := range append(warnings, se.Error(), se.Summary()) {
		if strings.Contains(text, "NET ") || strings.Contains(text, "vuln.go.dev") {
			t.Errorf("the NET line reached the failure: %q", text)
		}
	}
	if se.Reason != ReasonNoPackages {
		t.Errorf("Reason = %s, want no_packages (the NET line must not change the classification)", se.Reason)
	}
}

func TestChild_ExitsWhenTheParentIsGone(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdinW.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), vulnChildEnv+"=1", fakeChildEnv+"=block")
	cmd.Stdin = stdinR
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stdinR.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	select {
	case err := <-done:
		t.Fatalf("the child ended while its parent was still there: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	stdinW.Close() // the parent is gone
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the child kept running after its stdin closed")
	}
}

func TestChild_InProcessRunReleasesMemory(t *testing.T) {
	freed := 0
	prev := releaseMemory
	releaseMemory = func() { freed++ }
	t.Cleanup(func() { releaseMemory = prev })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out strings.Builder
	if err := runGovulncheckInProcess(ctx, os.Environ(), t.TempDir(), scanLevelPackage, &out, &out); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if freed != 1 {
		t.Errorf("releaseMemory ran %d times, want 1", freed)
	}
}

func TestChildStderr_SplitsAndBounds(t *testing.T) {
	var nets []string
	s := &childStderr{net: func(l string) { nets = append(nets, l) }}
	fmt.Fprint(s, "first\nNET GET a\r\nNET GET b\npanic: x\n")
	fmt.Fprint(s, strings.Repeat("y", childLineMax+100)+"\n") // an over-long line is cut
	for i := 0; i < 3*childTailMax/10; i++ {
		fmt.Fprintf(s, "line %05d\n", i)
	}
	fmt.Fprint(s, "last without newline")
	s.flush()
	if len(nets) != 2 || nets[0] != "NET GET a" {
		t.Errorf("nets = %q", nets)
	}
	if s.panicText() != "panic: x" {
		t.Errorf("panic line = %q", s.panicText())
	}
	tail := s.tailText()
	if len(tail) > childTailMax || !strings.HasSuffix(tail, "last without newline\n") || strings.Contains(tail, "NET ") || strings.HasPrefix(tail, "ine ") {
		t.Errorf("tail len %d, starts %q, ends %q", len(tail), tail[:10], tail[len(tail)-30:])
	}
}

func TestChild_NetworkLogRequestsReachTheParentsLog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer srv.Close()
	var buf bytes.Buffer
	netlog.Enable(&buf)
	t.Cleanup(netlog.Disable)

	warnings, err := passWithEnv(t, "http", fakeChildURLEnv+"="+srv.URL)
	se := asScanError(t, err)
	if !strings.Contains(buf.String(), "NET GET 127.0.0.1:") {
		t.Errorf("the child's request is missing from the parent's log: %q", buf.String())
	}
	if n := strings.Count(buf.String(), "\n"); n != 1 {
		t.Errorf("want one NET line, got %d: %q", n, buf.String())
	}
	for _, text := range append(warnings, se.Error(), se.Summary()) {
		if strings.Contains(text, "NET ") || strings.Contains(text, "127.0.0.1") {
			t.Errorf("the NET line reached the failure: %q", text)
		}
	}
	if se.Reason != ReasonNoPackages {
		t.Errorf("Reason = %s, want no_packages", se.Reason)
	}
}

func TestChild_NoNetworkLogMarkerWhenTheParentDoesNotLog(t *testing.T) {
	if netlog.Enabled() {
		t.Skip("a previous test enabled the global sink")
	}
	var buf bytes.Buffer
	prev := vulnChildNetHook
	vulnChildNetHook = func(line string) { buf.WriteString(line) } // would collect any NET line that came back
	t.Cleanup(func() { vulnChildNetHook = prev })

	warnings, _ := passWithEnv(t, "netlogstate")
	if len(warnings) == 0 || !strings.Contains(warnings[0], "netlog=false marker=\"\"") {
		t.Errorf("the child must not log its network when the parent does not: %q", warnings)
	}
	if buf.Len() != 0 {
		t.Errorf("a line reached the sink: %q", buf.String())
	}

	// and with the parent's log on, the child logs and the marker is gone for its own children
	netlog.Enable(&bytes.Buffer{})
	t.Cleanup(netlog.Disable)
	warnings, _ = passWithEnv(t, "netlogstate")
	if len(warnings) == 0 || !strings.Contains(warnings[0], "netlog=true marker=\"\"") {
		t.Errorf("the child must log its network when the parent does, and not pass the marker on: %q", warnings)
	}
}

func TestChild_CannotStartIsATypedFailureNotAFallback(t *testing.T) {
	prev := vulnChildExecutable
	vulnChildExecutable = func() (string, error) { return filepath.Join(t.TempDir(), "no-such-unisupply"), nil }
	t.Cleanup(func() { vulnChildExecutable = prev })

	warnings, err, freed := passWithChild(t, context.Background(), "block")
	se := asScanError(t, err)
	if se.Reason != ReasonUnknown || se.Kind != FailPermanent {
		t.Errorf("Kind/Reason = %v/%s, want permanent/unknown", se.Kind, se.Reason)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "starting govulncheck:") {
		t.Errorf("warnings = %q, want one that says starting govulncheck", warnings)
	}
	if freed != 0 {
		t.Errorf("releaseMemory ran %d times: the scan fell back to the in-process run", freed)
	}
}

func TestChild_ErrorIsOnlyItsErrorLines(t *testing.T) {
	warnings, err, _ := passWithChild(t, context.Background(), "noisyerror")
	se := asScanError(t, err)
	sameClass(t, se, childMultipleMains, nil)
	for _, text := range append(warnings, se.Error()) {
		if strings.Contains(text, "dial tcp") || strings.Contains(text, "429") {
			t.Errorf("stderr that is not the error reached the failure: %q", text)
		}
	}
}

func TestChild_StatusOneWithoutAnErrorIsACrash(t *testing.T) {
	warnings, err, _ := passWithChild(t, context.Background(), "exit1")
	se := asScanError(t, err)
	if se.Reason != ReasonInternalPanic || se.Kind != FailPermanent {
		t.Fatalf("Kind/Reason = %v/%s, want permanent/internal_panic", se.Kind, se.Reason)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "crashed (exit status 1)") {
		t.Errorf("warnings = %q, want the crash with its status", warnings)
	}
	if !strings.Contains(se.Error(), "init: config not found") {
		t.Errorf("the stderr tail should stay in the error: %q", se.Error())
	}
}

func TestChild_StubbornChildIsKilledAfterTheWaitDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	defer cancel()
	start := time.Now()
	_, err, _ := passWithChild(t, ctx, "stubborn")
	if d := time.Since(start); d > childWaitDelay+5*time.Second {
		t.Errorf("the scan took %v to return after the cancel, want about childWaitDelay (%v)", d, childWaitDelay)
	}
	sameClass(t, asScanError(t, err), context.Canceled.Error(), context.Canceled)
}

func TestChild_PanicAfterTheCancelIsStillTheCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	defer cancel()
	_, err, _ := passWithChild(t, ctx, "paniconcancel")
	sameClass(t, asScanError(t, err), context.Canceled.Error(), context.Canceled)
}

func TestChildExecutable_IsTheRunningImageOnLinux(t *testing.T) {
	got, err := childExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		if got != procSelfExe {
			t.Errorf("childExecutable() = %q, want %q", got, procSelfExe)
		}
		return
	}
	want, _ := os.Executable()
	if got != want {
		t.Errorf("childExecutable() = %q, want os.Executable() %q", got, want)
	}
}

func TestChildStderr_ErrorLines(t *testing.T) {
	s := &childStderr{}
	writeChildError(s, errors.New("govulncheck: loading packages:\n\n/x/b.go:3:6: main redeclared"))
	fmt.Fprint(s, "noise from an init function\nERR ")
	s.flush()
	if got, want := s.errorText(), "govulncheck: loading packages:\n\n/x/b.go:3:6: main redeclared\n\n"; got != want {
		t.Errorf("errorText = %q, want %q", got, want)
	}
	if tail := s.tailText(); tail != "noise from an init function\n" {
		t.Errorf("tail = %q, want only the noise", tail)
	}
	big := &childStderr{}
	for range 2 * childErrMax / 1000 {
		fmt.Fprint(big, childErrPrefix+strings.Repeat("e", 999)+"\n")
	}
	if n := len(big.errorText()); n > childErrMax {
		t.Errorf("errorText is %d bytes, want at most %d", n, childErrMax)
	}
}

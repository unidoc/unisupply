package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/vuln/scan"

	"github.com/unidoc/unisupply/pkg/netlog"
)

// vulnChildEnv is the environment variable that makes an executable run as the govulncheck child: it is set to "1" in
// the environment of the child that runGovulncheckChild starts. The marker is an environment variable and not an
// argument, so that the arguments of a host program are never read differently.
const vulnChildEnv = "UNISUPPLY_GOVULNCHECK_CHILD"

// vulnChildNetlogEnv is set to "1", next to vulnChildEnv, when the parent has --network-log on: the child then logs its
// own requests (govulncheck's, to vuln.go.dev) to its stderr, and the parent forwards the lines to its own log.
const vulnChildNetlogEnv = "UNISUPPLY_GOVULNCHECK_CHILD_NETLOG"

const (
	// childWaitDelay is how long a child that was asked to stop (its stdin closed) has before it is killed, and how long
	// Wait then lingers on its output pipes. It is longer than childStopGrace, so that the child can stop its `go list`
	// first.
	childWaitDelay = 5 * time.Second
	// childStopGrace is how long the child's own processes (`go list` and the compilers it runs) have to end after
	// SIGINT before the child kills them.
	childStopGrace = 2 * time.Second
	// childStoppedStatus is the exit status of a child that stopped because its stdin closed: the parent's context ended,
	// or the parent is gone.
	childStoppedStatus = 3
	// childTailMax is the most of the child's stderr that is kept (the end of it) when the child fails.
	childTailMax = 64 << 10
	// childLineMax is the longest stderr line that is kept; the rest of a longer line is dropped.
	childLineMax = 64 << 10
	// childPanicMax is the longest "panic:" line that is published.
	childPanicMax = 1 << 10
	// childNetPrefix starts a stderr line of the child that is a network-log line, not an error text.
	childNetPrefix = "NET "
	// childErrPrefix starts each line of the error that govulncheck returned, as the child writes it to stderr. Only
	// these lines are the error: the rest of stderr can hold anything the host's init functions wrote.
	childErrPrefix = "ERR "
	// childErrMax is the most of the error text that is kept (the start of it).
	childErrMax = 256 << 10
	// procSelfExe is, on Linux, the image the running process was started from.
	procSelfExe = "/proc/self/exe"
)

// vulnChildCapable is set by RunVulnChildIfRequested when the executable can serve as the govulncheck child, that is,
// when its main called the hook first thing.
var vulnChildCapable atomic.Bool

// vulnChildNetHook receives the network-log lines (those that start with "NET ") of the child's stderr. They never
// reach the failure message. By default they join this process's network log.
var vulnChildNetHook = netlog.Line

// vulnChildExecutable is the program that serves as the child. It is a variable so tests can point it somewhere else.
var vulnChildExecutable = childExecutable

// childExecutable is this executable. On Linux it is /proc/self/exe, which starts the image this process runs even when
// the file was replaced or removed since (a package upgrade under a long-running service): the path os.Executable gives
// would then start another build, one that may not call RunVulnChildIfRequested, and whose golang.org/x/vuln may not be
// the version ScanInfo reports.
func childExecutable() (string, error) {
	if runtime.GOOS == "linux" {
		if _, err := os.Stat(procSelfExe); err == nil {
			return procSelfExe, nil
		}
	}
	return os.Executable()
}

// vulnChildBody is what the child runs: govulncheck, in this process, with the given arguments. ctx ends when the child
// stops (its stdin closed). It is a variable so that tests can swap it for a fake that blocks, panics or fails.
//
// golang.org/x/vuln v1.9.0 does not hand ctx to the package loader, so ctx does not stop a `go list` that is running:
// vulnChildStopProcesses does.
var vulnChildBody = func(ctx context.Context, args []string) error {
	cmd := scan.Command(ctx, args...)
	cmd.Env = os.Environ()
	// Never the parent's pipe: govulncheck must not consume what the stdin watcher reads.
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}

// RunVulnChildIfRequested lets the executable serve as the process that runs govulncheck for a vulnerability scan. A
// program that scans (ScanVulnsWithOptions, or anything built on it) must call it first thing in main, before it parses
// flags or does any other work: when the executable was started as the child it runs govulncheck and exits, and never
// returns; otherwise it records that the executable can serve as a child and returns.
//
// govulncheck then runs in a child process of the same executable. A scan that is cancelled while govulncheck builds
// its call graph makes govulncheck panic in a goroutine of its own, which nothing in the scanning process can recover:
// in a child process that panic ends the child, and the scan returns a typed *ScanError instead of the host dying.
// A program that does not call it runs govulncheck in its own process, where a scan that is cancelled at the wrong
// moment can still crash it.
//
// The child is the same executable started again, so the package init functions of the host run in the child too:
// they must not start servers or open connections as a side effect. It shares nothing else with the host: what the host
// set up in code, such as a replaced http.DefaultTransport (a corporate CA, an authenticated proxy, a request policy),
// does not apply to govulncheck's requests to vuln.go.dev. Proxy settings in the environment (HTTPS_PROXY, NO_PROXY) do.
func RunVulnChildIfRequested() {
	if os.Getenv(vulnChildEnv) != "1" {
		vulnChildCapable.Store(true)
		return
	}
	os.Exit(runVulnChild())
}

// vulnChildStopProcesses stops the processes the child started. It is a variable so that tests can make a child that
// does not stop.
var vulnChildStopProcesses = stopChildProcesses

// runVulnChild is the child's main; it returns the exit status. Status 1 is an error that govulncheck returned (its
// lines are on stderr, each after childErrPrefix); childStoppedStatus is a child whose stdin closed; a panic ends the
// process with the runtime's status 2.
func runVulnChild() int {
	// The parent alone decides when the child stops, through its context: it closes our stdin. Signals that reach the
	// child as well do not stop it. Ctrl-C on a terminal reaches the whole process group, and a child that died of it
	// would be taken for a crash; a terminal that hangs up sends SIGHUP the same way, and a child that died of it would
	// leave its `go list` running; SIGTERM reaches it from a service manager that stops the whole group, while the host
	// may still finish its scans. The child catches these signals and does nothing with them. It catches them rather
	// than ignores them, because an ignored signal stays ignored in the processes the child starts, and the SIGINT that
	// stops them below would not.
	signal.Notify(make(chan os.Signal, 1), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	// The parent holds the write end of our stdin until its context ends or it has waited for us: EOF means the scan was
	// cancelled or the parent is gone, and a child that may hold several GB, and the `go list` it runs, must not be left
	// behind.
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		cancel()
		// `go list` runs in a process group of its own, which no signal to this process reaches, and the loader
		// does not see ctx: stop it here, or it keeps loading packages after this process is gone.
		vulnChildStopProcesses(childStopGrace)
		fmt.Fprintln(os.Stderr, "govulncheck child process stopped: its stdin closed")
		close(stopped)
		os.Exit(childStoppedStatus)
	}()
	if os.Getenv(vulnChildNetlogEnv) == "1" {
		// The parent logs the requests of its scan: log ours the same way, on stderr, where the parent reads them.
		netlog.Enable(os.Stderr)
	}
	_ = os.Unsetenv(vulnChildEnv)
	_ = os.Unsetenv(vulnChildNetlogEnv)
	err := vulnChildBody(ctx, os.Args[1:])
	if ctx.Err() != nil {
		// Stopping: what govulncheck returned is the stop itself. The process ends once its own processes are stopped.
		<-stopped
		return childStoppedStatus
	}
	if err != nil {
		writeChildError(os.Stderr, err)
		return 1
	}
	return 0
}

// writeChildError writes err to w one line at a time, each line after childErrPrefix, for the parent to tell apart from
// anything else on stderr.
func writeChildError(w io.Writer, err error) {
	var b strings.Builder
	for line := range strings.SplitSeq(err.Error(), "\n") {
		b.WriteString(childErrPrefix)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	_, _ = io.WriteString(w, b.String())
}

// childCrashError is a govulncheck child that did not end the way a child does: it panicked, was killed, or failed to
// finish its output. Its text is for people; the scan reports it as ReasonInternalPanic without classifying it.
type childCrashError struct {
	status    string // how the process ended: "exit status 2", "signal: killed"
	panicLine string // the first "panic:" line of its stderr, if any
	tail      string // the end of its stderr
}

// summary is the one line that is published: the status and the panic line.
func (e *childCrashError) summary() string {
	s := "govulncheck child process crashed (" + e.status + ")"
	if e.panicLine != "" {
		s += ": " + e.panicLine
	}
	return s
}

func (e *childCrashError) Error() string {
	if e.tail == "" {
		return e.summary()
	}
	return e.summary() + "\n" + e.tail
}

// runGovulncheckChild runs govulncheck at the given scan level in a child process of this executable and returns its
// error. A context that ends stops the child (its stdin closes, then a kill after childWaitDelay) and gives back the
// context's error, like the in-process run does for a context that has ended; a child that panicked, was killed, or ended without
// an error text gives a *childCrashError.
func runGovulncheckChild(ctx context.Context, env []string, dir, level string, stdout, _ io.Writer) error {
	exe, err := vulnChildExecutable()
	if err != nil {
		return fmt.Errorf("starting govulncheck: %w", err)
	}
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("starting govulncheck: %w", err)
	}
	defer stdinW.Close() // after Wait: the child sees EOF only when we are done with it, cancel it, or are gone

	if env == nil {
		env = os.Environ()
	}
	stderr := &childStderr{net: vulnChildNetHook}
	cmd := exec.CommandContext(ctx, exe, "-json", "-scan", level, "-C", dir, "./...")
	cmd.Args[0] = os.Args[0] // the name ps shows: the host's, not /proc/self/exe
	cmd.Env = append(slices.Clone(env), vulnChildEnv+"=1")
	if netlog.Enabled() {
		cmd.Env = append(cmd.Env, vulnChildNetlogEnv+"=1")
	}
	cmd.Stdin = stdinR
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Cancel = stdinW.Close // the child stops on EOF; a signal would also stop it when it was not ours
	cmd.WaitDelay = childWaitDelay
	err = cmd.Start()
	_ = stdinR.Close() // the child has its own copy
	if err != nil {
		// A context that ended before the child started: the in-process run gives that context's error too.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("starting govulncheck: %w", err)
	}
	waitErr := cmd.Wait()
	stderr.flush()
	if waitErr == nil {
		return nil
	}
	// A context that ended is the cause, whatever the killed child left behind.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) && exitErr.ExitCode() == 1 {
		// govulncheck returned an error: its text, the way the in-process run gives it. Status 1 without one is not the
		// child's (a log.Fatal in an init function of the host, a TerminateProcess on Windows): a crash.
		if text := strings.TrimSpace(stderr.errorText()); text != "" {
			return errors.New(text)
		}
	}
	return &childCrashError{status: waitErr.Error(), panicLine: stderr.panicText(), tail: strings.TrimSpace(stderr.tailText())}
}

// childStderr splits the child's stderr into lines as they come. Network-log lines go to net; error lines (childErrPrefix)
// are the error text, without the prefix; the rest is kept for a crash, bounded: the first "panic:" line, and the end
// (childTailMax bytes) of what follows, so that a goroutine dump of any size never reaches the failure rules.
type childStderr struct {
	net func(string)

	mu        sync.Mutex
	partial   []byte // the line being read
	dropping  bool   // the line being read is over childLineMax: the rest of it is dropped
	panicLine string
	tail      []byte
	errText   []byte // the error lines, without the prefix, up to childErrMax
}

func (s *childStderr) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			s.add(p)
			break
		}
		s.add(p[:i])
		s.endLine()
		p = p[i+1:]
	}
	return n, nil
}

func (s *childStderr) add(b []byte) {
	if s.dropping {
		return
	}
	if room := childLineMax - len(s.partial); len(b) > room {
		b, s.dropping = b[:room], true
	}
	s.partial = append(s.partial, b...)
}

func (s *childStderr) endLine() {
	line := strings.TrimSuffix(string(s.partial), "\r")
	s.partial, s.dropping = s.partial[:0], false
	if strings.HasPrefix(line, childNetPrefix) {
		if s.net != nil {
			s.net(line)
		}
		return
	}
	if text, ok := strings.CutPrefix(line, childErrPrefix); ok {
		if len(s.errText)+len(text) < childErrMax {
			s.errText = append(s.errText, text...)
			s.errText = append(s.errText, '\n')
		}
		return
	}
	if s.panicLine == "" && strings.HasPrefix(line, "panic:") {
		s.panicLine = line
	}
	s.tail = append(s.tail, line...)
	s.tail = append(s.tail, '\n')
	if len(s.tail) > 2*childTailMax {
		s.tail = cutTail(s.tail)
	}
}

// flush ends a last line that has no newline.
func (s *childStderr) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.partial) > 0 {
		s.endLine()
	}
}

// cutTail keeps the last childTailMax bytes of b, from a line start and a character start, in a new slice.
func cutTail(b []byte) []byte {
	if len(b) <= childTailMax {
		return b
	}
	b = b[len(b)-childTailMax:]
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
	}
	for len(b) > 0 && !utf8.RuneStart(b[0]) {
		b = b[1:]
	}
	return slices.Clone(b)
}

// errorText is the error that the child wrote, one line per error line.
func (s *childStderr) errorText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.errText)
}

func (s *childStderr) tailText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(cutTail(s.tail))
}

// panicText is the first "panic:" line, cut to childPanicMax bytes at a character boundary.
func (s *childStderr) panicText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := s.panicLine
	if len(line) <= childPanicMax {
		return line
	}
	cut := childPanicMax
	for !utf8.RuneStart(line[cut]) {
		cut--
	}
	return line[:cut] + "..."
}

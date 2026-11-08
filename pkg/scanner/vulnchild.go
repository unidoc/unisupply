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
	// childWaitDelay bounds how long Wait lingers on the child's output pipes after the child is gone or killed:
	// govulncheck's loader runs `go list` grandchildren that can keep an inherited pipe open past a SIGKILL.
	childWaitDelay = 5 * time.Second
	// childTailMax is the most of the child's stderr that is kept (the end of it) when the child fails.
	childTailMax = 64 << 10
	// childLineMax is the longest stderr line that is kept; the rest of a longer line is dropped.
	childLineMax = 64 << 10
	// childPanicMax is the longest "panic:" line that is published.
	childPanicMax = 1 << 10
	// childNetPrefix starts a stderr line of the child that is a network-log line, not an error text.
	childNetPrefix = "NET "
)

// vulnChildCapable is set by RunVulnChildIfRequested when the executable can serve as the govulncheck child, that is,
// when its main called the hook first thing.
var vulnChildCapable atomic.Bool

// vulnChildNetHook receives the network-log lines (those that start with "NET ") of the child's stderr. They never
// reach the failure message. By default they join this process's network log.
var vulnChildNetHook = netlog.Line

// vulnChildExecutable is the program that serves as the child. It is a variable so tests can point it somewhere else.
var vulnChildExecutable = os.Executable

// vulnChildBody is what the child runs: govulncheck, in this process, with the given arguments. It is a variable so
// that tests can swap it for a fake that blocks, panics or fails.
var vulnChildBody = func(args []string) error {
	cmd := scan.Command(context.Background(), args...)
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
// they must not start servers or open connections as a side effect.
func RunVulnChildIfRequested() {
	if os.Getenv(vulnChildEnv) != "1" {
		vulnChildCapable.Store(true)
		return
	}
	os.Exit(runVulnChild())
}

// runVulnChild is the child's main; it returns the exit status. Status 1 is an error that govulncheck returned (its
// text is on stderr); a panic ends the process with the runtime's status 2.
func runVulnChild() int {
	// The parent controls the child's lifetime through its context. Ctrl-C on a terminal reaches the whole process
	// group, and a child that died of it would be taken for a crash.
	signal.Ignore(os.Interrupt, syscall.SIGTERM)
	// The parent holds the write end of our stdin until it has waited for us: EOF means the parent is gone, and a child
	// that may hold several GB must not be left behind.
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(1)
	}()
	if os.Getenv(vulnChildNetlogEnv) == "1" {
		// The parent logs the requests of its scan: log ours the same way, on stderr, where the parent reads them.
		netlog.Enable(os.Stderr)
	}
	_ = os.Unsetenv(vulnChildEnv)
	_ = os.Unsetenv(vulnChildNetlogEnv)
	if err := vulnChildBody(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	return 0
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
// error. A context that ends kills the child and gives back the context's error, like the in-process run does for a
// context that has ended; a child that panicked or was killed gives a *childCrashError.
func runGovulncheckChild(ctx context.Context, env []string, dir, level string, stdout, _ io.Writer) error {
	exe, err := vulnChildExecutable()
	if err != nil {
		return fmt.Errorf("starting govulncheck: %w", err)
	}
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("starting govulncheck: %w", err)
	}
	defer stdinW.Close() // after Wait: the child sees EOF only when we are done with it, or gone

	if env == nil {
		env = os.Environ()
	}
	stderr := &childStderr{net: vulnChildNetHook}
	cmd := exec.CommandContext(ctx, exe, "-json", "-scan", level, "-C", dir, "./...")
	cmd.Env = append(slices.Clone(env), vulnChildEnv+"=1")
	if netlog.Enabled() {
		cmd.Env = append(cmd.Env, vulnChildNetlogEnv+"=1")
	}
	cmd.Stdin = stdinR
	cmd.Stdout = stdout
	cmd.Stderr = stderr
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
		// govulncheck returned an error: its text, the way the in-process run gives it.
		text := strings.TrimSpace(stderr.tailText())
		if text == "" {
			text = "govulncheck child process exited with status 1 and no message"
		}
		return errors.New(text)
	}
	return &childCrashError{status: waitErr.Error(), panicLine: stderr.panicText(), tail: strings.TrimSpace(stderr.tailText())}
}

// childStderr splits the child's stderr into lines as they come. Network-log lines go to net; the rest is kept for the
// failure message, bounded: the first "panic:" line, and the end (childTailMax bytes) of what follows, so that a goroutine
// dump of any size never reaches the failure rules.
type childStderr struct {
	net func(string)

	mu        sync.Mutex
	partial   []byte // the line being read
	dropping  bool   // the line being read is over childLineMax: the rest of it is dropped
	panicLine string
	tail      []byte
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

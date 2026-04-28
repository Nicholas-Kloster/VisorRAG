// Package sandbox is the public facade for sandboxed command execution.
// All probes flow through Execute → runsc.RunSandboxed → gVisor OCI bundle.
package sandbox

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/Nicholas-Kloster/visor-rag/internal/sandbox/runsc"
)

type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
}

// Executor lazily resolves runsc on first use and reuses the path thereafter.
type Executor struct {
	runscPath string
	timeout   time.Duration
}

func New(timeout time.Duration) (*Executor, error) {
	p, err := runsc.Detect()
	if err != nil {
		return nil, err
	}
	if !runsc.IsAvailable() {
		return nil, fmt.Errorf("runsc found at %s but --version failed; check installation", p)
	}
	return &Executor{runscPath: p, timeout: timeout}, nil
}

// Execute runs cmd with args inside a gVisor sandbox. cmd is resolved on the
// host via $PATH and bind-mounted read-only inside the container.
func (e *Executor) Execute(ctx context.Context, cmd string, args ...string) (*Result, error) {
	return e.ExecuteStdin(ctx, nil, cmd, args...)
}

// ExecuteStdin is Execute plus a piped stdin. Used by tools like BARE that
// read findings JSON from stdin. Pass nil stdin for normal invocation.
func (e *Executor) ExecuteStdin(ctx context.Context, stdin io.Reader, cmd string, args ...string) (*Result, error) {
	full := append([]string{cmd}, args...)
	r, err := runsc.RunSandboxed(ctx, e.runscPath, full, e.timeout, stdin)
	if err != nil {
		return nil, err
	}
	return &Result{
		ExitCode: r.ExitCode,
		Stdout:   string(r.Stdout),
		Stderr:   string(r.Stderr),
		Duration: r.Duration,
	}, nil
}

// MustNew is for tests / examples; panics if runsc is missing.
func MustNew(timeout time.Duration) *Executor {
	e, err := New(timeout)
	if err != nil {
		panic(err)
	}
	return e
}

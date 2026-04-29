// Package sandbox is the public facade for sandboxed command execution.
// All probes flow through Execute → runsc.RunSandboxed → gVisor OCI bundle.
package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
// DefaultMounts are bind-mounts applied to every sandboxed invocation —
// auto-detected at New() time for known data corpora (nuclei-templates).
type Executor struct {
	runscPath     string
	timeout       time.Duration
	DefaultMounts []runsc.BindMount
}

// BindMount re-exports the runsc type so callers don't have to import the
// runsc subpackage directly.
type BindMount = runsc.BindMount

func New(timeout time.Duration) (*Executor, error) {
	p, err := runsc.Detect()
	if err != nil {
		return nil, err
	}
	if !runsc.IsAvailable() {
		return nil, fmt.Errorf("runsc found at %s but --version failed; check installation", p)
	}
	e := &Executor{runscPath: p, timeout: timeout}
	e.DefaultMounts = autoDetectDataMounts()
	return e, nil
}

// autoDetectDataMounts probes for known data corpora on the host that
// sandboxed tools might need. Each found path is exposed read-only at a
// fixed container path.
//
// Currently checked:
//   - $VISORRAG_NUCLEI_TEMPLATES or ~/nuclei-templates → /nuclei-templates
//   - $VISORRAG_OSV_DATABASE or ~/.cache/osv-scanner   → /osv-cache
func autoDetectDataMounts() []runsc.BindMount {
	var out []runsc.BindMount
	for _, mp := range []struct {
		envKey, defaultRel, containerPath string
	}{
		{"VISORRAG_NUCLEI_TEMPLATES", "nuclei-templates", "/nuclei-templates"},
		{"VISORRAG_OSV_DATABASE", ".cache/osv-scanner", "/osv-cache"},
	} {
		host := os.Getenv(mp.envKey)
		if host == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				continue
			}
			host = filepath.Join(home, mp.defaultRel)
		}
		if info, err := os.Stat(host); err == nil && info.IsDir() {
			out = append(out, runsc.BindMount{HostPath: host, ContainerPath: mp.containerPath})
		}
	}
	return out
}

// Execute runs cmd with args inside a gVisor sandbox. cmd is resolved on the
// host via $PATH and bind-mounted read-only inside the container.
func (e *Executor) Execute(ctx context.Context, cmd string, args ...string) (*Result, error) {
	return e.ExecuteStdin(ctx, nil, cmd, args...)
}

// ExecuteStdin is Execute plus a piped stdin. Used by tools like BARE that
// read findings JSON from stdin. Pass nil stdin for normal invocation.
// Default mounts are applied automatically.
func (e *Executor) ExecuteStdin(ctx context.Context, stdin io.Reader, cmd string, args ...string) (*Result, error) {
	full := append([]string{cmd}, args...)
	r, err := runsc.RunSandboxed(ctx, e.runscPath, full, e.timeout, stdin, e.DefaultMounts)
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

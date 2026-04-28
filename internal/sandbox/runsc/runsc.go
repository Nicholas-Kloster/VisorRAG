// Package runsc executes commands inside a gVisor (runsc) sandbox using a full
// OCI bundle. Adapted from VisorGraph (github.com/Nicholas-Kloster/VisorGraph)
// internal/sandbox/runsc — the same hardened pattern: readonly rootfs, dropped
// capabilities (CAP_NET_RAW only), rlimits, namespace isolation, runs as
// nobody:nogroup. The probe binary is bind-mounted read-only at /rg-probe.
//
// Why a full OCI bundle and not `runsc do --`: `runsc do` is a one-shot
// convenience that inherits much of the host environment. The bundle path
// gives explicit control over rootfs, mounts, capabilities, rlimits, and
// namespaces — the security guarantee VisorRAG depends on.
//
// Network is host-shared so probes can reach the target without veth plumbing;
// gVisor's syscall interception still isolates the probe from the host kernel.
package runsc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const ociVersion = "1.0.2-dev"

type ExecResult struct {
	ContainerID string
	ExitCode    int
	Stdout      []byte
	Stderr      []byte
	Duration    time.Duration
}

func Detect() (string, error) {
	candidates := []string{
		"/usr/bin/runsc",
		"/usr/local/bin/runsc",
		"/opt/runsc/runsc",
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}
	if p, err := exec.LookPath("runsc"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("runsc not found in common paths or $PATH — install gVisor: https://gvisor.dev/docs/user_guide/install/")
}

func IsAvailable() bool {
	p, err := Detect()
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, p, "--version").Run() == nil
}

// RunSandboxed executes cmd inside a gVisor container. cmd[0] is resolved via
// exec.LookPath; cmd[1:] are passed as arguments to the bind-mounted binary at
// /rg-probe inside the container.
func RunSandboxed(ctx context.Context, runscPath string, cmd []string, timeout time.Duration) (*ExecResult, error) {
	if len(cmd) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	binPath, err := exec.LookPath(cmd[0])
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", cmd[0], err)
	}

	bundle, err := os.MkdirTemp("", "vr-runsc-*")
	if err != nil {
		return nil, fmt.Errorf("create bundle dir: %w", err)
	}
	defer os.RemoveAll(bundle)

	rootfs := filepath.Join(bundle, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return nil, err
	}

	cid := containerID()
	cfg := buildOCIConfig(rootfs, binPath, cmd[1:])
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), cfgJSON, 0o644); err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runscCmd := exec.CommandContext(runCtx, runscPath,
		"--rootless",
		"--network=host",
		"run",
		"--bundle", bundle,
		cid,
	)

	start := time.Now()
	stdout, err := runscCmd.Output()
	dur := time.Since(start)

	res := &ExecResult{
		ContainerID: cid,
		Stdout:      stdout,
		Duration:    dur,
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
			res.Stderr = ee.Stderr
		} else {
			return nil, fmt.Errorf("runsc: %w", err)
		}
	}
	return res, nil
}

func containerID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "vr-" + hex.EncodeToString(b)
}

type ociConfig struct {
	OCIVersion string     `json:"ociVersion"`
	Process    ociProcess `json:"process"`
	Root       ociRoot    `json:"root"`
	Hostname   string     `json:"hostname,omitempty"`
	Mounts     []ociMount `json:"mounts,omitempty"`
	Linux      ociLinux   `json:"linux"`
}

type ociProcess struct {
	Terminal        bool             `json:"terminal"`
	User            ociUser          `json:"user"`
	Args            []string         `json:"args"`
	Env             []string         `json:"env,omitempty"`
	Cwd             string           `json:"cwd"`
	Capabilities    *ociCapabilities `json:"capabilities,omitempty"`
	NoNewPrivileges bool             `json:"noNewPrivileges"`
	Rlimits         []ociRlimit      `json:"rlimits,omitempty"`
}

type ociUser struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

type ociCapabilities struct {
	Bounding    []string `json:"bounding,omitempty"`
	Effective   []string `json:"effective,omitempty"`
	Permitted   []string `json:"permitted,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
}

type ociRlimit struct {
	Type string `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}

type ociRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type ociMount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options,omitempty"`
}

type ociLinux struct {
	Namespaces    []ociNamespace `json:"namespaces,omitempty"`
	MaskedPaths   []string       `json:"maskedPaths,omitempty"`
	ReadonlyPaths []string       `json:"readonlyPaths,omitempty"`
	Resources     *ociResources  `json:"resources,omitempty"`
}

type ociNamespace struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
}

type ociResources struct {
	Memory *ociMemory `json:"memory,omitempty"`
}

type ociMemory struct {
	Limit int64 `json:"limit"`
}

func buildOCIConfig(rootfs, binPath string, args []string) *ociConfig {
	mounts := []ociMount{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{
			Destination: "/tmp",
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "nodev", "mode=1777", "size=64m"},
		},
		{
			Destination: "/dev/null",
			Type:        "bind",
			Source:      "/dev/null",
			Options:     []string{"bind", "rw"},
		},
		{
			Destination: "/rg-probe",
			Type:        "bind",
			Source:      binPath,
			Options:     []string{"bind", "ro"},
		},
		{
			// /etc/resolv.conf for DNS — probes need name resolution.
			Destination: "/etc/resolv.conf",
			Type:        "bind",
			Source:      "/etc/resolv.conf",
			Options:     []string{"bind", "ro"},
		},
	}

	for _, libDir := range []string{
		"/lib", "/lib64",
		"/usr/lib", "/usr/lib64",
		"/lib/x86_64-linux-gnu",
		"/usr/lib/x86_64-linux-gnu",
	} {
		if info, err := os.Stat(libDir); err == nil && info.IsDir() {
			mounts = append(mounts, ociMount{
				Destination: libDir,
				Type:        "bind",
				Source:      libDir,
				Options:     []string{"rbind", "ro"},
			})
		}
	}

	return &ociConfig{
		OCIVersion: ociVersion,
		Process: ociProcess{
			Terminal: false,
			User:     ociUser{UID: 65534, GID: 65534},
			Args:     append([]string{"/rg-probe"}, args...),
			Env:      []string{"PATH=/", "HOME=/tmp", "USER=nobody"},
			Cwd:      "/tmp",
			Capabilities: &ociCapabilities{
				Bounding:  []string{"CAP_NET_RAW"},
				Effective: []string{"CAP_NET_RAW"},
				Permitted: []string{"CAP_NET_RAW"},
			},
			NoNewPrivileges: true,
			Rlimits: []ociRlimit{
				{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024},
				{Type: "RLIMIT_NPROC", Hard: 64, Soft: 64},
			},
		},
		Root:     ociRoot{Path: rootfs, Readonly: true},
		Hostname: "vr-sandbox",
		Mounts:   mounts,
		Linux: ociLinux{
			Namespaces: []ociNamespace{
				{Type: "pid"},
				{Type: "ipc"},
				{Type: "uts"},
				{Type: "mount"},
			},
			MaskedPaths: []string{
				"/proc/kcore",
				"/proc/sysrq-trigger",
				"/proc/latency_stats",
				"/proc/timer_list",
			},
			ReadonlyPaths: []string{
				"/proc/bus", "/proc/fs", "/proc/irq",
				"/proc/sys", "/proc/sysrq-trigger",
			},
			Resources: &ociResources{
				Memory: &ociMemory{Limit: 512 * 1024 * 1024},
			},
		},
	}
}

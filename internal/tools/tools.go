// Package tools registers sandboxed probe wrappers exposed to the agent.
// Every wrapper shells out to a CLI binary inside the gVisor sandbox so
// the agent process (which holds API keys, RAG memory, and decision state)
// is fully isolated from probe execution.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Nicholas-Kloster/visor-rag/internal/sandbox"
)

// Tool is the agent-facing interface. The agent picks a tool by Name(),
// hands it a JSON args blob, and gets back a textual observation that
// goes into the next ReAct turn.
type Tool interface {
	Name() string
	Description() string
	ArgsSchema() string // JSON-schema-ish hint for the LLM
	Run(ctx context.Context, jsonArgs string) (string, error)
}

// Registry holds all sandboxed tools available to the agent.
type Registry struct {
	exec  *sandbox.Executor
	tools map[string]Tool
	order []string
}

func NewRegistry(exec *sandbox.Executor) *Registry {
	r := NewEmpty()
	r.exec = exec
	r.Register(&httpxTool{exec: exec})
	r.Register(&nucleiTool{exec: exec})
	r.Register(&asnmapTool{exec: exec})
	r.Register(&naabuTool{exec: exec})
	return r
}

// NewEmpty constructs a registry with no tools wired. Useful for tests
// that supply their own Tool implementations, or for callers extending the
// default toolset before Engine construction.
func NewEmpty() *Registry {
	return &Registry{tools: map[string]Tool{}}
}

// Register adds a Tool to the registry. Names must be unique; later
// registrations overwrite earlier ones.
func (r *Registry) Register(t Tool) {
	if _, exists := r.tools[t.Name()]; !exists {
		r.order = append(r.order, t.Name())
	}
	r.tools[t.Name()] = t
}

func (r *Registry) Get(name string) (Tool, bool) { t, ok := r.tools[name]; return t, ok }
func (r *Registry) Names() []string              { return append([]string(nil), r.order...) }

// Manifest renders a compact text manifest for the LLM prompt.
func (r *Registry) Manifest() string {
	var sb strings.Builder
	for _, n := range r.order {
		t := r.tools[n]
		fmt.Fprintf(&sb, "- %s: %s\n  args: %s\n", t.Name(), t.Description(), t.ArgsSchema())
	}
	return sb.String()
}

// ---------- httpx ----------

type httpxArgs struct {
	Target string `json:"target"`
	Ports  string `json:"ports,omitempty"`
}
type httpxTool struct{ exec *sandbox.Executor }

func (h *httpxTool) Name() string { return "httpx" }
func (h *httpxTool) Description() string {
	return "HTTP/TLS surface fingerprint — title, status, tech stack, TLS cert SANs."
}
func (h *httpxTool) ArgsSchema() string {
	return `{"target":"<ip|host|cidr>","ports":"<comma-list, default 80,443,8080,8443>"}`
}
func (h *httpxTool) Run(ctx context.Context, jsonArgs string) (string, error) {
	var a httpxArgs
	if err := json.Unmarshal([]byte(jsonArgs), &a); err != nil {
		return "", fmt.Errorf("parse args: %w", err)
	}
	if a.Target == "" {
		return "", fmt.Errorf("target required")
	}
	if a.Ports == "" {
		a.Ports = "80,443,8080,8443,8000,8888"
	}
	args := []string{
		"-u", a.Target,
		"-ports", a.Ports,
		"-title", "-status-code", "-tech-detect", "-tls-probe",
		"-follow-redirects",
		"-timeout", "8",
		"-silent",
		"-no-color",
		"-json",
	}
	return runAndFormat(ctx, h.exec, "httpx", args, 60*time.Second)
}

// ---------- nuclei ----------

type nucleiArgs struct {
	Target   string   `json:"target"`
	Tags     []string `json:"tags,omitempty"`
	Severity string   `json:"severity,omitempty"`
}
type nucleiTool struct{ exec *sandbox.Executor }

func (n *nucleiTool) Name() string { return "nuclei" }
func (n *nucleiTool) Description() string {
	return "Templated vulnerability + misconfig scanner. Use specific -tags to keep it targeted."
}
func (n *nucleiTool) ArgsSchema() string {
	return `{"target":"<url|host>","tags":["exposure","tech","cve"],"severity":"low,medium,high,critical"}`
}
func (n *nucleiTool) Run(ctx context.Context, jsonArgs string) (string, error) {
	var a nucleiArgs
	if err := json.Unmarshal([]byte(jsonArgs), &a); err != nil {
		return "", fmt.Errorf("parse args: %w", err)
	}
	if a.Target == "" {
		return "", fmt.Errorf("target required")
	}
	args := []string{
		"-u", a.Target,
		"-silent",
		"-no-color",
		"-jsonl",
		"-disable-update-check",
		"-rate-limit", "50",
	}
	if len(a.Tags) > 0 {
		args = append(args, "-tags", strings.Join(a.Tags, ","))
	}
	if a.Severity != "" {
		args = append(args, "-severity", a.Severity)
	}
	return runAndFormat(ctx, n.exec, "nuclei", args, 5*time.Minute)
}

// ---------- asnmap ----------

type asnmapArgs struct {
	Target string `json:"target"`
}
type asnmapTool struct{ exec *sandbox.Executor }

func (a *asnmapTool) Name() string         { return "asnmap" }
func (a *asnmapTool) Description() string  { return "Resolve target to ASN, owner, CIDR." }
func (a *asnmapTool) ArgsSchema() string   { return `{"target":"<ip|domain|asn>"}` }
func (a *asnmapTool) Run(ctx context.Context, jsonArgs string) (string, error) {
	var args asnmapArgs
	if err := json.Unmarshal([]byte(jsonArgs), &args); err != nil {
		return "", fmt.Errorf("parse args: %w", err)
	}
	if args.Target == "" {
		return "", fmt.Errorf("target required")
	}
	return runAndFormat(ctx, a.exec, "asnmap", []string{"-i", args.Target, "-silent", "-json"}, 30*time.Second)
}

// ---------- naabu ----------

type naabuArgs struct {
	Target string `json:"target"`
	Top    int    `json:"top,omitempty"`
}
type naabuTool struct{ exec *sandbox.Executor }

func (n *naabuTool) Name() string         { return "naabu" }
func (n *naabuTool) Description() string  { return "TCP port scanner. Use small top-N for quick recon." }
func (n *naabuTool) ArgsSchema() string   { return `{"target":"<ip|host>","top":100}` }
func (n *naabuTool) Run(ctx context.Context, jsonArgs string) (string, error) {
	var a naabuArgs
	if err := json.Unmarshal([]byte(jsonArgs), &a); err != nil {
		return "", fmt.Errorf("parse args: %w", err)
	}
	if a.Target == "" {
		return "", fmt.Errorf("target required")
	}
	if a.Top <= 0 {
		a.Top = 100
	}
	args := []string{
		"-host", a.Target,
		"-top-ports", fmt.Sprintf("%d", a.Top),
		"-silent",
		"-json",
		"-no-color",
	}
	return runAndFormat(ctx, n.exec, "naabu", args, 90*time.Second)
}

// ---------- shared exec helper ----------

func runAndFormat(ctx context.Context, exec *sandbox.Executor, cmd string, args []string, timeout time.Duration) (string, error) {
	subCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r, err := exec.Execute(subCtx, cmd, args...)
	if err != nil {
		return "", fmt.Errorf("sandboxed %s: %w", cmd, err)
	}
	out := strings.TrimSpace(r.Stdout)
	if out == "" && r.Stderr != "" {
		out = "(no stdout) stderr: " + strings.TrimSpace(r.Stderr)
	}
	if out == "" {
		out = fmt.Sprintf("(empty result; exit=%d duration=%s)", r.ExitCode, r.Duration)
	}
	return out, nil
}

// Package tools registers sandboxed probe wrappers exposed to the agent.
// Every wrapper shells out to a CLI binary inside the gVisor sandbox so
// the agent process (which holds API keys, RAG memory, and decision state)
// is fully isolated from probe execution.
//
// The default registry exposes NuClide-authored tools (visorgraph, aimap)
// rather than commodity scanners. ProjectDiscovery wrappers (httpxTool,
// nucleiTool, asnmapTool, naabuTool) remain defined below for ad-hoc
// registration but are NOT in the default lineup — they were dropped after
// 7 live runs against scanme.nmap.org surfaced PDCP auth walls, template
// directories, top-port preset rejections, and Python venv name conflicts
// that NuClide tools sidestep by design.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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

// NewRegistry builds the default NuClide tool lineup. visorgraph is the
// general-purpose recon engine (CT logs + HTTP + TLS + exposure
// classification). aimap is the AI/ML-specific scanner. Both are Go static
// binaries authored under the NuClide umbrella; both produce dense JSON
// observations the agent can reason over directly.
func NewRegistry(exec *sandbox.Executor) *Registry {
	r := NewEmpty()
	r.exec = exec
	r.Register(&visorgraphTool{exec: exec})
	r.Register(&aimapTool{exec: exec})
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

// ---------- visorgraph (NuClide recon engine) ----------

type visorgraphArgs struct {
	Target   string `json:"target"`
	NoActive bool   `json:"no_active,omitempty"`
}
type visorgraphTool struct{ exec *sandbox.Executor }

func (v *visorgraphTool) Name() string { return "visorgraph" }
func (v *visorgraphTool) Description() string {
	return "Infrastructure recon engine. CT log enumeration, HTTP probes, TLS analysis, exposure classification. Returns a typed provenance graph as compact JSON. First reach for general targets — IPs or domains. Pass no_active=true for passive-only when stealth matters."
}
func (v *visorgraphTool) ArgsSchema() string {
	return `{"target":"<ip|domain>","no_active":false}`
}
func (v *visorgraphTool) Run(ctx context.Context, jsonArgs string) (string, error) {
	var a visorgraphArgs
	if err := json.Unmarshal([]byte(jsonArgs), &a); err != nil {
		return "", fmt.Errorf("parse args: %w", err)
	}
	if a.Target == "" {
		return "", fmt.Errorf("target required")
	}
	args := []string{}
	if isIPLiteral(a.Target) {
		args = append(args, "-ip", a.Target)
	} else {
		args = append(args, "-domain", a.Target)
	}
	args = append(args, "-no-stream") // compact final graph; full JSONL stream blows our token budget
	if a.NoActive {
		args = append(args, "-no-active")
	}
	return runAndFormat(ctx, v.exec, "visorgraph", args, 90*time.Second)
}

// ---------- aimap (NuClide AI/ML scanner) ----------

type aimapArgs struct {
	Target string `json:"target"`
	Ports  string `json:"ports,omitempty"`
}
type aimapTool struct{ exec *sandbox.Executor }

func (a *aimapTool) Name() string { return "aimap" }
func (a *aimapTool) Description() string {
	return "AI/ML infrastructure scanner. Fingerprints LLM endpoints, vector databases, model servers, agent platforms. Default port set covers Ollama/Triton/vLLM/ChromaDB/Qdrant/Weaviate/Milvus and 25+ other AI services. Reach when the target signals AI/ML or when visorgraph surfaces such ports."
}
func (a *aimapTool) ArgsSchema() string {
	return `{"target":"<ip|host|cidr>","ports":"<comma-list, optional override>"}`
}
func (a *aimapTool) Run(ctx context.Context, jsonArgs string) (string, error) {
	var args aimapArgs
	if err := json.Unmarshal([]byte(jsonArgs), &args); err != nil {
		return "", fmt.Errorf("parse args: %w", err)
	}
	if args.Target == "" {
		return "", fmt.Errorf("target required")
	}
	cmdArgs := []string{"-target", args.Target, "-o", "/dev/stdout"}
	if args.Ports != "" {
		cmdArgs = append(cmdArgs, "-ports", args.Ports)
	}
	return runAndFormat(ctx, a.exec, "aimap", cmdArgs, 60*time.Second)
}

// isIPLiteral returns true if s parses as a v4 or v6 address.
func isIPLiteral(s string) bool {
	return net.ParseIP(s) != nil
}

// ---------- httpx (DEPRECATED — not registered by default) ----------

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
	// Ports accepts any of:
	//   "80,443"          → explicit list      → -port 80,443
	//   "1-1000"          → explicit range     → -port 1-1000
	//   "top-100"|"100"   → top-100 preset     → -top-ports 100
	//   "top-1000"|"1000" → top-1000 preset    → -top-ports 1000
	//   "full"|"top-full" → all 65k ports      → -top-ports full
	//   ""                → default top-100
	Ports string `json:"ports,omitempty"`
}
type naabuTool struct{ exec *sandbox.Executor }

func (n *naabuTool) Name() string        { return "naabu" }
func (n *naabuTool) Description() string { return "TCP port scanner. Default top-100 for fast recon; pass explicit list/range for targeted sweeps." }
func (n *naabuTool) ArgsSchema() string {
	return `{"target":"<ip|host>","ports":"<spec: 80,443 or 1-1000 or top-100|top-1000|full; default top-100>"}`
}
func (n *naabuTool) Run(ctx context.Context, jsonArgs string) (string, error) {
	var a naabuArgs
	if err := json.Unmarshal([]byte(jsonArgs), &a); err != nil {
		return "", fmt.Errorf("parse args: %w", err)
	}
	if a.Target == "" {
		return "", fmt.Errorf("target required")
	}
	args := []string{"-host", a.Target}
	args = append(args, naabuPortFlag(a.Ports)...)
	args = append(args, "-silent", "-json", "-no-color")
	return runAndFormat(ctx, n.exec, "naabu", args, 90*time.Second)
}

// naabuPortFlag maps a free-form ports spec to naabu CLI flags.
// Naabu's -top-ports only accepts the preset values {100, 1000, full};
// arbitrary numeric values must go through -port. Earlier the wrapper
// passed any int directly to -top-ports, which broke when llama-3.3
// asked for top: 10 (run #6, commit d1b630a era).
func naabuPortFlag(spec string) []string {
	spec = strings.TrimSpace(strings.ToLower(spec))
	switch spec {
	case "", "top-100", "100":
		return []string{"-top-ports", "100"}
	case "top-1000", "1000":
		return []string{"-top-ports", "1000"}
	case "full", "top-full":
		return []string{"-top-ports", "full"}
	}
	// Anything else: treat as explicit port list/range (e.g. "80,443" or "1-65535").
	return []string{"-port", spec}
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

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
	"bytes"
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

// NewRegistry builds the default NuClide tool lineup.
//
//   - visorgraph: general infra recon (CT logs + HTTP + TLS + exposure
//     classification). Default reach for unknown targets.
//   - aimap:      AI/ML-specific scanner (LLM endpoints, vector DBs, model
//     servers, agent platforms — 36 service fingerprints).
//   - menlohunt:  GCP External Attack Surface Management (5-phase scan with
//     attack chain detection). Reach when target signals Google Cloud.
//   - bare:       post-recon exploit ranking. Takes finding descriptions,
//     returns ranked Metasploit modules via embedded BERT semantic search
//     against a 3,904-module corpus. Use after recon tools have produced
//     concrete findings.
//
// All four are NuClide-authored binaries. visorgraph/aimap/menlohunt are
// Go static; bare is Rust. All produce structured JSON the agent can
// reason over.
func NewRegistry(exec *sandbox.Executor) *Registry {
	r := NewEmpty()
	r.exec = exec
	r.Register(&visorgraphTool{exec: exec})
	r.Register(&aimapTool{exec: exec})
	r.Register(&menlohuntTool{exec: exec})
	r.Register(&bareTool{exec: exec})
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

// ---------- menlohunt (NuClide GCP EASM) ----------

type menlohuntArgs struct {
	Target string `json:"target"`
	NoICMP bool   `json:"no_icmp,omitempty"`
}
type menlohuntTool struct{ exec *sandbox.Executor }

func (m *menlohuntTool) Name() string { return "menlohunt" }
func (m *menlohuntTool) Description() string {
	return "GCP External Attack Surface Management. 5-phase scan: ports, raw protocols (Redis/MongoDB/Memcached), HTTP fingerprinting (Kubelets/Docker/MLflow), TLS analysis (extracts internal IP leaks + GCP project IDs from cert SANs), GCP-specific surface (Metadata API, GCS, Firebase). Built-in attack chain detection. Reach when target ASN/IP suggests Google Cloud, or when visorgraph cert SANs surface a GCP project ID."
}
func (m *menlohuntTool) ArgsSchema() string {
	return `{"target":"<ip-or-hostname>","no_icmp":false}`
}
func (m *menlohuntTool) Run(ctx context.Context, jsonArgs string) (string, error) {
	var a menlohuntArgs
	if err := json.Unmarshal([]byte(jsonArgs), &a); err != nil {
		return "", fmt.Errorf("parse args: %w", err)
	}
	if a.Target == "" {
		return "", fmt.Errorf("target required")
	}
	// menlohunt's scan subcommand takes -ip only. Resolve hostname → first
	// A record on the host before crossing into the sandbox. DNS lookup
	// here is a benign host-side operation.
	ip := a.Target
	if !isIPLiteral(a.Target) {
		addrs, err := net.LookupHost(a.Target)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", a.Target, err)
		}
		if len(addrs) == 0 {
			return "", fmt.Errorf("no addresses for %s", a.Target)
		}
		ip = addrs[0]
	}
	args := []string{"scan", "-ip", ip}
	if a.NoICMP {
		args = append(args, "-no-icmp")
	}
	return runAndFormat(ctx, m.exec, "menlohunt", args, 90*time.Second)
}

// ---------- bare (NuClide exploit ranking) ----------

type bareArgs struct {
	Findings []bareFinding `json:"findings"`
	Top      int           `json:"top,omitempty"` // top-N modules per finding (default 3)
}

type bareFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Target      string `json:"target,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

// bareInput is the BARE v1 envelope schema (see INPUT_FORMAT.md in the BARE repo).
type bareInput struct {
	Version  int               `json:"version"`
	Source   string            `json:"source"`
	Findings []bareInputFinding `json:"findings"`
}

type bareInputFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Target      string `json:"target,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

type bareTool struct{ exec *sandbox.Executor }

func (b *bareTool) Name() string { return "bare" }
func (b *bareTool) Description() string {
	return "Post-recon exploit ranking via embedded BERT semantic search. Provide a list of findings (title + description text); BARE returns the top-N most relevant Metasploit modules per finding from its 3,904-module corpus. Reach AFTER recon tools (visorgraph/aimap/menlohunt) have produced concrete findings — not as a primary recon step."
}
func (b *bareTool) ArgsSchema() string {
	return `{"findings":[{"title":"<short name>","description":"<rich text — what the vuln is, what's affected, how it's exploited>","target":"<optional>","severity":"<info|low|medium|high|critical, optional>"}],"top":3}`
}
func (b *bareTool) Run(ctx context.Context, jsonArgs string) (string, error) {
	var a bareArgs
	if err := json.Unmarshal([]byte(jsonArgs), &a); err != nil {
		return "", fmt.Errorf("parse args: %w", err)
	}
	if len(a.Findings) == 0 {
		return "", fmt.Errorf("findings required (at least one)")
	}

	// Build the BARE v1 input envelope.
	input := bareInput{
		Version:  1,
		Source:   "visor-rag",
		Findings: make([]bareInputFinding, 0, len(a.Findings)),
	}
	for i, f := range a.Findings {
		if strings.TrimSpace(f.Description) == "" {
			return "", fmt.Errorf("finding %d: description required", i)
		}
		input.Findings = append(input.Findings, bareInputFinding{
			ID:          fmt.Sprintf("vrf-%d", i+1),
			Title:       f.Title,
			Description: f.Description,
			Target:      f.Target,
			Severity:    f.Severity,
		})
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("encode bare input: %w", err)
	}

	cmdArgs := []string{}
	if a.Top > 0 {
		cmdArgs = append(cmdArgs, "--top", fmt.Sprintf("%d", a.Top))
	}

	subCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	r, err := b.exec.ExecuteStdin(subCtx, bytes.NewReader(payload), "bare", cmdArgs...)
	if err != nil {
		return "", fmt.Errorf("sandboxed bare: %w", err)
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

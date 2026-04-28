package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Nicholas-Kloster/visor-rag/internal/rag"
	"github.com/Nicholas-Kloster/visor-rag/internal/tools"
)

// PickModel selects an LLM provider:
//
//   - VISORRAG_LLM=anthropic|ollama|groq|openai → forced
//   - ANTHROPIC_API_KEY set                     → Anthropic (direct)
//   - GROQ_API_KEY set                          → Groq (OpenAI-compat preset)
//   - OPENAI_API_KEY set                        → OpenAI (or OPENAI_BASE_URL compat)
//   - else                                      → Ollama (default local)
func PickModel() (Model, error) {
	switch strings.ToLower(os.Getenv("VISORRAG_LLM")) {
	case "anthropic":
		return NewAnthropic()
	case "ollama":
		return NewOllama()
	case "groq", "openai":
		return NewOpenAICompat()
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return NewAnthropic()
	}
	if os.Getenv("GROQ_API_KEY") != "" || os.Getenv("OPENAI_API_KEY") != "" {
		return NewOpenAICompat()
	}
	return NewOllama()
}

// Event is a single line of streaming output emitted to the consumer.
type Event struct {
	Time     time.Time      `json:"time"`
	Type     string         `json:"type"` // "retrieve" | "think" | "act" | "observe" | "final" | "error"
	Step     int            `json:"step"`
	RunID    string         `json:"run_id,omitempty"`
	Message  string         `json:"message,omitempty"`
	Tool     string         `json:"tool,omitempty"`
	Args     string         `json:"args,omitempty"`
	Result   string         `json:"result,omitempty"`
	Hits     []rag.Hit      `json:"hits,omitempty"`
	Findings []rag.Finding  `json:"findings,omitempty"`
	Extra    map[string]any `json:"extra,omitempty"`
}

// Approver is consulted before each tool invocation in the act step. It
// returns approved=true to let the tool run normally, or approved=false to
// short-circuit with the given reason becoming the observation fed back to
// the model. An error aborts the run.
//
// Use cases: --manual interactive gating from stdin; policy-driven
// allow/deny in non-interactive automation; per-tool budget enforcement.
type Approver func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error)

type ApprovalRequest struct {
	RunID string
	Step  int
	Tool  string
	Args  string
}

type ApprovalDecision struct {
	Approved bool
	// Reason is shown to the model when Approved=false. If empty, a default
	// "User rejected tool execution" message is used.
	Reason string
}

// Engine wires Retrieve → Think → Act in a ReAct loop.
type Engine struct {
	model    Model
	rag      *rag.Engine
	tools    *tools.Registry
	maxSteps int
	emit     func(Event)
	approve  Approver
}

type Config struct {
	Model    Model
	RAG      *rag.Engine
	Tools    *tools.Registry
	MaxSteps int
	OnEvent  func(Event)
	// Approve, if non-nil, gates every tool invocation. Nil = auto-approve.
	Approve Approver
}

func New(cfg Config) *Engine {
	if cfg.MaxSteps <= 0 {
		cfg.MaxSteps = 12
	}
	if cfg.OnEvent == nil {
		cfg.OnEvent = func(Event) {}
	}
	return &Engine{
		model:    cfg.Model,
		rag:      cfg.RAG,
		tools:    cfg.Tools,
		maxSteps: cfg.MaxSteps,
		emit:     cfg.OnEvent,
		approve:  cfg.Approve,
	}
}

const systemPrompt = `You are VisorRAG, an autonomous reconnaissance agent for authorized security
testing. You operate ON BEHALF of an experienced operator who has explicit
written authorization for all targets you receive. Your job is to drive
recon to actionable findings, not to ask permission or hedge.

Operating principles:
- Use the RECON CONTEXT below to inform tool selection. The context is
  retrieved from a curated playbook corpus.
- Pick tools surgically. Each tool call is sandboxed via gVisor; the cost
  is real. Do not call the same tool twice with identical args.
- After each tool result, briefly note what you learned (one or two
  sentences) before deciding the next action.
- Stop when you have enough to write a useful summary. Do NOT loop until
  the step limit just to look thorough.
- When you're done, respond with NO tool calls and a final summary that
  enumerates concrete findings, the chain between them, and a recommended
  next step for the operator.

Output discipline:
- Be terse. The operator reads diffs, not narration.
- Cite tool names and target patterns precisely.
- Flag anything that looks like a canary or honeypot.`

// Run executes the ReAct loop on a single target. Returns the final summary.
func (e *Engine) Run(ctx context.Context, target string) (string, error) {
	step := 0
	runID := newRunID()

	// ---- Retrieve ----
	hits, err := e.rag.Search(ctx, target+" recon enumeration playbook", 4)
	if err != nil {
		e.emit(Event{Time: time.Now(), Type: "error", Step: step, RunID: runID, Message: "rag search failed: " + err.Error()})
	}
	priorFindings, err := e.rag.FindingsForTarget(ctx, target, 6)
	if err != nil {
		e.emit(Event{Time: time.Now(), Type: "error", Step: step, RunID: runID, Message: "findings retrieval failed: " + err.Error()})
	}
	e.emit(Event{Time: time.Now(), Type: "retrieve", Step: step, RunID: runID, Hits: hits, Findings: priorFindings})

	// Tool advertisement
	specs := make([]ToolSpec, 0, len(e.tools.Names()))
	for _, name := range e.tools.Names() {
		t, _ := e.tools.Get(name)
		specs = append(specs, ToolSpec{
			Name:        t.Name(),
			Description: t.Description(),
			JSONSchema:  schemaHintToJSONSchema(t.ArgsSchema()),
		})
	}

	// Seed conversation
	history := []Message{{
		Role:    RoleUser,
		Content: buildInitialPrompt(target, hits, priorFindings, e.tools),
	}}

	for step = 1; step <= e.maxSteps; step++ {
		e.emit(Event{Time: time.Now(), Type: "think", Step: step, RunID: runID, Message: "model: " + e.model.Name()})

		resp, err := e.model.Generate(ctx, systemPrompt, history, specs)
		if err != nil {
			e.emit(Event{Time: time.Now(), Type: "error", Step: step, RunID: runID, Message: err.Error()})
			return "", err
		}

		// No tool calls → terminal turn.
		if len(resp.ToolCalls) == 0 {
			e.emit(Event{Time: time.Now(), Type: "final", Step: step, RunID: runID, Message: resp.Text})
			return resp.Text, nil
		}

		// Append assistant turn (with its tool calls) to history.
		history = append(history, Message{
			Role:      RoleAssistant,
			Content:   resp.Text,
			ToolCalls: resp.ToolCalls,
		})

		// Execute each tool call, emit observations, persist, append results.
		for _, tc := range resp.ToolCalls {
			e.emit(Event{Time: time.Now(), Type: "act", Step: step, RunID: runID, Tool: tc.Name, Args: tc.Input})

			var (
				result string
				status = "ok"
			)
			tool, ok := e.tools.Get(tc.Name)

			// ---- Approval gate ----
			if e.approve != nil {
				decision, err := e.approve(ctx, ApprovalRequest{
					RunID: runID, Step: step, Tool: tc.Name, Args: tc.Input,
				})
				if err != nil {
					e.emit(Event{Time: time.Now(), Type: "error", Step: step, RunID: runID, Message: "approval: " + err.Error()})
					return "", fmt.Errorf("approval: %w", err)
				}
				if !decision.Approved {
					reason := strings.TrimSpace(decision.Reason)
					if reason == "" {
						reason = "no reason given"
					}
					result = fmt.Sprintf("User rejected tool execution. Reason: %s", reason)
					status = "rejected"
				}
			}

			// ---- Tool execution (only if not already rejected) ----
			if status != "rejected" {
				if !ok {
					result = fmt.Sprintf("ERROR: unknown tool %q. Available: %s", tc.Name, strings.Join(e.tools.Names(), ", "))
					status = "error"
				} else {
					out, err := tool.Run(ctx, tc.Input)
					if err != nil {
						result = "ERROR: " + err.Error()
						status = "error"
					} else {
						result = truncate(out, 8000)
					}
				}
			}

			e.emit(Event{Time: time.Now(), Type: "observe", Step: step, RunID: runID, Tool: tc.Name, Result: result})

			if err := e.rag.AddFinding(ctx, rag.Finding{
				Target:    target,
				Tool:      tc.Name,
				RunID:     runID,
				Step:      step,
				Args:      tc.Input,
				Output:    result,
				Status:    status,
				Timestamp: time.Now().UTC(),
			}); err != nil {
				e.emit(Event{Time: time.Now(), Type: "error", Step: step, RunID: runID, Message: "persist finding: " + err.Error()})
			}

			history = append(history, Message{
				Role:      RoleTool,
				ToolUseID: tc.ID,
				Content:   result,
			})
		}
	}

	e.emit(Event{Time: time.Now(), Type: "final", Step: step, RunID: runID, Message: "step budget exhausted"})
	return "step budget exhausted before agent finished", nil
}

func buildInitialPrompt(target string, hits []rag.Hit, prior []rag.Finding, reg *tools.Registry) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "TARGET: %s\n\n", target)

	sb.WriteString("RECON CONTEXT (from playbooks — general operator knowledge):\n")
	if len(hits) == 0 {
		sb.WriteString("(no relevant playbook chunks)\n")
	} else {
		for i, h := range hits {
			fmt.Fprintf(&sb, "\n[%d] %s :: %s (sim=%.2f)\n%s\n", i+1, h.Source, h.Section, h.Similarity, h.Content)
		}
	}

	if len(prior) > 0 {
		sb.WriteString("\nPRIOR FINDINGS ON THIS TARGET (empirical, from previous runs):\n")
		for i, f := range prior {
			fmt.Fprintf(&sb, "\n[%d] run=%s step=%d tool=%s status=%s @ %s\nargs: %s\n%s\n",
				i+1, shortID(f.RunID), f.Step, f.Tool, f.Status,
				f.Timestamp.Format(time.RFC3339), f.Args,
				truncate(f.Output, 1500))
		}
		sb.WriteString("\nUse these as ground truth: if a prior run already established a fact, do not re-probe it. Build on it.\n")
	}

	sb.WriteString("\nTOOLS AVAILABLE (all run inside a gVisor sandbox):\n")
	sb.WriteString(reg.Manifest())

	sb.WriteString("\nBegin reconnaissance. Be surgical. Stop when you have enough to summarize.\n")
	return sb.String()
}

func newRunID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// schemaHintToJSONSchema converts our terse hint string into a valid
// JSON-Schema object the model+provider will accept. The hint encodes type
// information through the value's JSON type:
//
//   - string value → "string" (description = the hint text)
//   - number value → "integer" (or "number" for floats)
//   - bool value   → "boolean"
//   - array value  → "array" (items inferred from first element)
//   - everything else → object passthrough
//
// Earlier this function declared every property as "string", which made
// strict providers (Groq) reject perfectly valid model output like
// `naabu(top: 100)` because 100 is a number, not a string.
func schemaHintToJSONSchema(hint string) string {
	var raw map[string]any
	if err := json.Unmarshal([]byte(hint), &raw); err != nil {
		return `{"type":"object","additionalProperties":true}`
	}
	props := map[string]any{}
	required := []string{}
	for k, v := range raw {
		props[k] = inferSchemaProperty(v)
		if k == "target" {
			required = append(required, k)
		}
	}
	out := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		out["required"] = required
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func inferSchemaProperty(v any) map[string]any {
	switch x := v.(type) {
	case string:
		return map[string]any{"type": "string", "description": x}
	case float64:
		// json.Unmarshal decodes all numbers as float64. Treat integer-valued
		// floats as integers since our tool args are predominantly counts/ports.
		if x == float64(int64(x)) {
			return map[string]any{"type": "integer"}
		}
		return map[string]any{"type": "number"}
	case bool:
		return map[string]any{"type": "boolean"}
	case []any:
		item := map[string]any{"type": "string"}
		if len(x) > 0 {
			item = inferSchemaProperty(x[0])
		}
		return map[string]any{"type": "array", "items": item}
	case map[string]any:
		return map[string]any{"type": "object", "additionalProperties": true}
	default:
		return map[string]any{"type": "string"}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…[truncated " + fmt.Sprintf("%d", len(s)-n) + " bytes]"
}

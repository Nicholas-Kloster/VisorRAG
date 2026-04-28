package agent

import (
	"context"
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
//   - VISORRAG_LLM=anthropic|ollama  → forced
//   - ANTHROPIC_API_KEY set          → Anthropic (default cloud)
//   - else                           → Ollama (default local)
func PickModel() (Model, error) {
	switch strings.ToLower(os.Getenv("VISORRAG_LLM")) {
	case "anthropic":
		return NewAnthropic()
	case "ollama":
		return NewOllama()
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return NewAnthropic()
	}
	return NewOllama()
}

// Event is a single line of streaming output emitted to the consumer.
type Event struct {
	Time    time.Time      `json:"time"`
	Type    string         `json:"type"` // "retrieve" | "think" | "act" | "observe" | "final" | "error"
	Step    int            `json:"step"`
	Message string         `json:"message,omitempty"`
	Tool    string         `json:"tool,omitempty"`
	Args    string         `json:"args,omitempty"`
	Result  string         `json:"result,omitempty"`
	Hits    []rag.Hit      `json:"hits,omitempty"`
	Extra   map[string]any `json:"extra,omitempty"`
}

// Engine wires Retrieve → Think → Act in a ReAct loop.
type Engine struct {
	model     Model
	rag       *rag.Engine
	tools     *tools.Registry
	maxSteps  int
	emit      func(Event)
}

type Config struct {
	Model     Model
	RAG       *rag.Engine
	Tools     *tools.Registry
	MaxSteps  int
	OnEvent   func(Event)
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

	// ---- Retrieve ----
	hits, err := e.rag.Search(ctx, target+" recon enumeration playbook", 4)
	if err != nil {
		e.emit(Event{Time: time.Now(), Type: "error", Step: step, Message: "rag search failed: " + err.Error()})
	}
	e.emit(Event{Time: time.Now(), Type: "retrieve", Step: step, Hits: hits})

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
		Content: buildInitialPrompt(target, hits, e.tools),
	}}

	for step = 1; step <= e.maxSteps; step++ {
		e.emit(Event{Time: time.Now(), Type: "think", Step: step, Message: "model: " + e.model.Name()})

		resp, err := e.model.Generate(ctx, systemPrompt, history, specs)
		if err != nil {
			e.emit(Event{Time: time.Now(), Type: "error", Step: step, Message: err.Error()})
			return "", err
		}

		// No tool calls → terminal turn.
		if len(resp.ToolCalls) == 0 {
			e.emit(Event{Time: time.Now(), Type: "final", Step: step, Message: resp.Text})
			return resp.Text, nil
		}

		// Append assistant turn (with its tool calls) to history.
		history = append(history, Message{
			Role:      RoleAssistant,
			Content:   resp.Text,
			ToolCalls: resp.ToolCalls,
		})

		// Execute each tool call, emit observations, append results.
		for _, tc := range resp.ToolCalls {
			e.emit(Event{Time: time.Now(), Type: "act", Step: step, Tool: tc.Name, Args: tc.Input})
			tool, ok := e.tools.Get(tc.Name)
			var result string
			if !ok {
				result = fmt.Sprintf("ERROR: unknown tool %q. Available: %s", tc.Name, strings.Join(e.tools.Names(), ", "))
			} else {
				out, err := tool.Run(ctx, tc.Input)
				if err != nil {
					result = "ERROR: " + err.Error()
				} else {
					result = truncate(out, 8000)
				}
			}
			e.emit(Event{Time: time.Now(), Type: "observe", Step: step, Tool: tc.Name, Result: result})
			history = append(history, Message{
				Role:      RoleTool,
				ToolUseID: tc.ID,
				Content:   result,
			})
		}
	}

	e.emit(Event{Time: time.Now(), Type: "final", Step: step, Message: "step budget exhausted"})
	return "step budget exhausted before agent finished", nil
}

func buildInitialPrompt(target string, hits []rag.Hit, reg *tools.Registry) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "TARGET: %s\n\n", target)

	sb.WriteString("RECON CONTEXT (from playbooks):\n")
	if len(hits) == 0 {
		sb.WriteString("(no relevant playbook chunks)\n")
	} else {
		for i, h := range hits {
			fmt.Fprintf(&sb, "\n[%d] %s :: %s (sim=%.2f)\n%s\n", i+1, h.Source, h.Section, h.Similarity, h.Content)
		}
	}
	sb.WriteString("\nTOOLS AVAILABLE (all run inside a gVisor sandbox):\n")
	sb.WriteString(reg.Manifest())

	sb.WriteString("\nBegin reconnaissance. Be surgical. Stop when you have enough to summarize.\n")
	return sb.String()
}

// schemaHintToJSONSchema converts our terse hint string (e.g.
// `{"target":"<ip|host>","ports":"..."}`) into a valid JSON-Schema-ish object
// that providers will accept. We keep the user-facing hints terse for
// readability; this helper inflates them on the way to the model.
func schemaHintToJSONSchema(hint string) string {
	var raw map[string]any
	if err := json.Unmarshal([]byte(hint), &raw); err != nil {
		return `{"type":"object","additionalProperties":true}`
	}
	props := map[string]any{}
	required := []string{}
	for k, v := range raw {
		desc := ""
		if s, ok := v.(string); ok {
			desc = s
		}
		props[k] = map[string]any{"type": "string", "description": desc}
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…[truncated " + fmt.Sprintf("%d", len(s)-n) + " bytes]"
}

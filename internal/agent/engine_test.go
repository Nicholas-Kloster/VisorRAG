package agent

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nicholas-Kloster/visor-rag/internal/rag"
	"github.com/Nicholas-Kloster/visor-rag/internal/tools"

	// Side-effect: register embedded playbooks with the RAG engine so
	// rag.NewWithEmbedder finds chunks to index.
	_ "github.com/Nicholas-Kloster/visor-rag/playbooks"
)

// ------------- fake embedder -------------

const embedDim = 64

// fakeEmbedder hashes whitespace-separated tokens into bins and
// L2-normalizes the result. Deterministic, in-process, no network.
// Similar text → similar vectors, which is enough for the loop test.
func fakeEmbedder(_ context.Context, text string) ([]float32, error) {
	vec := make([]float32, embedDim)
	for _, tok := range strings.Fields(strings.ToLower(text)) {
		h := fnv.New32a()
		_, _ = h.Write([]byte(tok))
		bin := int(h.Sum32() % embedDim)
		vec[bin] += 1.0
	}
	var norm float64
	for _, v := range vec {
		norm += float64(v) * float64(v)
	}
	if norm == 0 {
		vec[0] = 1
		return vec, nil
	}
	norm = math.Sqrt(norm)
	for i := range vec {
		vec[i] = float32(float64(vec[i]) / norm)
	}
	return vec, nil
}

// ------------- fake tool -------------

type fakeTool struct {
	mu        sync.Mutex
	name      string
	desc      string
	schema    string
	handler   func(args string) (string, error)
	gotArgs   []string
	callCount int
}

func (f *fakeTool) Name() string        { return f.name }
func (f *fakeTool) Description() string { return f.desc }
func (f *fakeTool) ArgsSchema() string  { return f.schema }

func (f *fakeTool) Run(_ context.Context, args string) (string, error) {
	f.mu.Lock()
	f.callCount++
	f.gotArgs = append(f.gotArgs, args)
	f.mu.Unlock()
	if f.handler == nil {
		return "ok", nil
	}
	return f.handler(args)
}

// ------------- helpers -------------

func mustRAG(t *testing.T) *rag.Engine {
	t.Helper()
	r, err := rag.NewWithEmbedder(context.Background(), fakeEmbedder, "fake-bag-of-words")
	if err != nil {
		t.Fatalf("rag init: %v", err)
	}
	return r
}

func mustPersistentRAG(t *testing.T, stateDir string) *rag.Engine {
	t.Helper()
	r, err := rag.NewWithOptions(context.Background(), rag.Options{
		Embedder:      fakeEmbedder,
		EmbedderLabel: "fake-bag-of-words",
		StateDir:      stateDir,
	})
	if err != nil {
		t.Fatalf("rag init (persistent): %v", err)
	}
	return r
}

type capturedEvents struct {
	mu sync.Mutex
	ev []Event
}

func (c *capturedEvents) on(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ev = append(c.ev, e)
}

func (c *capturedEvents) types() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.ev))
	for i, e := range c.ev {
		out[i] = e.Type
	}
	return out
}

// ------------- tests -------------

// TestSingleTurnNoTools: model emits a final summary on turn 1 with no
// tool calls. Verifies the terminal-without-tool path.
func TestSingleTurnNoTools(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	model := newFakeModel("oneshot", &Response{Text: "summary: nothing to do", StopReason: "end_turn"})

	cap := &capturedEvents{}
	eng := New(Config{
		Model:    model,
		RAG:      mustRAG(t),
		Tools:    tools.NewEmpty(),
		MaxSteps: 4,
		OnEvent:  cap.on,
	})

	out, err := eng.Run(ctx, "192.0.2.1")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "summary") {
		t.Errorf("expected summary in output, got %q", out)
	}
	if got := cap.types(); !equalSlice(got, []string{"retrieve", "think", "final"}) {
		t.Errorf("event sequence = %v, want [retrieve think final]", got)
	}
	if model.callCount() != 1 {
		t.Errorf("expected 1 model call, got %d", model.callCount())
	}
}

// TestMultiTurnToolUse: model calls a fake tool, observes its result,
// then emits a final summary. Verifies retrieve→think→act→observe→think→final
// sequence and that the tool result is threaded back into model history
// with the correct tool_use_id.
func TestMultiTurnToolUse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	probe := &fakeTool{
		name:    "probe",
		desc:    "fake probe that returns canned data",
		schema:  `{"target":"<host>"}`,
		handler: func(args string) (string, error) { return "probe-result-for:" + args, nil },
	}

	model := newFakeModel("react",
		&Response{
			ToolCalls: []ToolCall{{ID: "tu_001", Name: "probe", Input: `{"target":"192.0.2.1"}`}},
		},
		&Response{Text: "summary: probe completed", StopReason: "end_turn"},
	)

	reg := tools.NewEmpty()
	reg.Register(probe)

	cap := &capturedEvents{}
	eng := New(Config{
		Model:    model,
		RAG:      mustRAG(t),
		Tools:    reg,
		MaxSteps: 4,
		OnEvent:  cap.on,
	})

	out, err := eng.Run(ctx, "192.0.2.1")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "probe completed") {
		t.Errorf("unexpected final summary: %q", out)
	}
	if probe.callCount != 1 {
		t.Errorf("probe called %d times, want 1", probe.callCount)
	}
	if !strings.Contains(probe.gotArgs[0], "192.0.2.1") {
		t.Errorf("probe got args %q, expected to contain target", probe.gotArgs[0])
	}

	wantSeq := []string{"retrieve", "think", "act", "observe", "think", "final"}
	if got := cap.types(); !equalSlice(got, wantSeq) {
		t.Errorf("event sequence = %v, want %v", got, wantSeq)
	}

	// On its second call the model should see: initial user prompt,
	// assistant turn with tool_use, then tool result with matching id.
	hist := model.lastHistory()
	if len(hist) != 3 {
		t.Fatalf("expected 3-message history on second call, got %d", len(hist))
	}
	if hist[0].Role != RoleUser {
		t.Errorf("hist[0].Role=%v, want user", hist[0].Role)
	}
	if hist[1].Role != RoleAssistant || len(hist[1].ToolCalls) != 1 || hist[1].ToolCalls[0].ID != "tu_001" {
		t.Errorf("hist[1] missing or wrong tool_call: %+v", hist[1])
	}
	if hist[2].Role != RoleTool || hist[2].ToolUseID != "tu_001" {
		t.Errorf("hist[2] tool result mis-threaded: role=%v id=%q", hist[2].Role, hist[2].ToolUseID)
	}
	if !strings.Contains(hist[2].Content, "probe-result-for:") {
		t.Errorf("hist[2] content didn't carry tool output: %q", hist[2].Content)
	}
}

// TestUnknownToolHandled: model calls a tool name that isn't registered.
// Engine must surface the error in the observation, feed it back to the
// model, and let the loop continue.
func TestUnknownToolHandled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	model := newFakeModel("unknown-tool",
		&Response{
			ToolCalls: []ToolCall{{ID: "tu_404", Name: "ghosttool", Input: `{}`}},
		},
		&Response{Text: "abandoning, tool unavailable", StopReason: "end_turn"},
	)

	cap := &capturedEvents{}
	eng := New(Config{
		Model:    model,
		RAG:      mustRAG(t),
		Tools:    tools.NewEmpty(),
		MaxSteps: 4,
		OnEvent:  cap.on,
	})
	if _, err := eng.Run(ctx, "x"); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Find the observe event and check its result body
	var observed string
	for _, e := range cap.ev {
		if e.Type == "observe" {
			observed = e.Result
		}
	}
	if !strings.Contains(observed, "unknown tool") {
		t.Errorf("observe event missing 'unknown tool' marker: %q", observed)
	}
}

// TestStepBudgetExhaustion: model never stops calling tools. Engine must
// terminate at MaxSteps with an explanatory final event.
func TestStepBudgetExhaustion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tool := &fakeTool{name: "loop", desc: "loops forever", schema: `{"x":"y"}`,
		handler: func(args string) (string, error) { return "looped", nil }}

	// Build a script with the same tool call repeated past MaxSteps.
	script := make([]*Response, 0, 8)
	for i := 0; i < 8; i++ {
		script = append(script, &Response{
			ToolCalls: []ToolCall{{ID: fmt.Sprintf("tu_%d", i), Name: "loop", Input: `{"x":"y"}`}},
		})
	}
	model := newFakeModel("looper", script...)

	reg := tools.NewEmpty()
	reg.Register(tool)

	cap := &capturedEvents{}
	eng := New(Config{
		Model:    model,
		RAG:      mustRAG(t),
		Tools:    reg,
		MaxSteps: 3,
		OnEvent:  cap.on,
	})

	out, err := eng.Run(ctx, "x")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "step budget exhausted") {
		t.Errorf("expected budget-exhausted summary, got %q", out)
	}
	if tool.callCount != 3 {
		t.Errorf("tool calls = %d, want 3 (== MaxSteps)", tool.callCount)
	}
}

// TestRAGContextInjected: the initial prompt sent to the model must
// include the playbook hits the engine retrieved.
func TestRAGContextInjected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	model := newFakeModel("inspect", &Response{Text: "done", StopReason: "end_turn"})
	eng := New(Config{
		Model:    model,
		RAG:      mustRAG(t),
		Tools:    tools.NewEmpty(),
		MaxSteps: 2,
		OnEvent:  func(Event) {},
	})

	if _, err := eng.Run(ctx, "aws ec2 cloud target"); err != nil {
		t.Fatalf("run: %v", err)
	}

	hist := model.lastHistory()
	if len(hist) == 0 || hist[0].Role != RoleUser {
		t.Fatalf("expected user prompt as first message, got %+v", hist)
	}
	prompt := hist[0].Content
	if !strings.Contains(prompt, "RECON CONTEXT") {
		t.Errorf("prompt missing RECON CONTEXT block: %q", prompt[:min(200, len(prompt))])
	}
	if !strings.Contains(prompt, "TOOLS AVAILABLE") {
		t.Errorf("prompt missing TOOLS AVAILABLE block")
	}
}

// TestEventTimingSane: emitted events should have monotonically
// non-decreasing timestamps and step numbers consistent with type.
func TestEventTimingSane(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	model := newFakeModel("time", &Response{Text: "ok", StopReason: "end_turn"})
	cap := &capturedEvents{}
	eng := New(Config{
		Model:    model,
		RAG:      mustRAG(t),
		Tools:    tools.NewEmpty(),
		MaxSteps: 2,
		OnEvent:  cap.on,
	})
	if _, err := eng.Run(ctx, "x"); err != nil {
		t.Fatalf("run: %v", err)
	}

	var prev time.Time
	for i, e := range cap.ev {
		if i > 0 && e.Time.Before(prev) {
			t.Errorf("event %d (%s) has time before previous (%v < %v)", i, e.Type, e.Time, prev)
		}
		prev = e.Time
	}
}

// TestPersistedFindingsCarryAcrossRuns: two sequential agent runs against
// the same target sharing a state-dir. The second run's initial prompt
// must contain the first run's tool output. Proves the persistence path
// closes the loop end-to-end: AddFinding writes to disk, FindingsForTarget
// reads them back, buildInitialPrompt injects them into history.
func TestPersistedFindingsCarryAcrossRuns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	stateDir := t.TempDir()
	const targetIP = "192.0.2.42"
	const probeOutput = "OPEN: 192.0.2.42:8080 banner=NUCLIDE-CANARY-7F3"

	probe := &fakeTool{
		name:    "probe",
		desc:    "fake probe returning a uniquely identifiable banner",
		schema:  `{"target":"<host>"}`,
		handler: func(args string) (string, error) { return probeOutput, nil },
	}

	// ---- Run 1: model calls probe, then summarizes. ----
	{
		model := newFakeModel("run1",
			&Response{ToolCalls: []ToolCall{{ID: "tu_a", Name: "probe", Input: `{"target":"192.0.2.42"}`}}},
			&Response{Text: "summary: scanned, banner captured", StopReason: "end_turn"},
		)
		reg := tools.NewEmpty()
		reg.Register(probe)

		eng := New(Config{
			Model:    model,
			RAG:      mustPersistentRAG(t, stateDir),
			Tools:    reg,
			MaxSteps: 4,
			OnEvent:  func(Event) {},
		})
		if _, err := eng.Run(ctx, targetIP); err != nil {
			t.Fatalf("run 1: %v", err)
		}
	}

	// ---- Run 2: fresh agent + fresh RAG engine, same state-dir. ----
	model2 := newFakeModel("run2", &Response{Text: "summary: prior data sufficient", StopReason: "end_turn"})
	reg2 := tools.NewEmpty()
	reg2.Register(probe)

	rag2 := mustPersistentRAG(t, stateDir)
	if got := rag2.FindingsCount(); got < 1 {
		t.Fatalf("findings collection did not persist across constructions: count=%d", got)
	}

	eng2 := New(Config{
		Model:    model2,
		RAG:      rag2,
		Tools:    reg2,
		MaxSteps: 4,
		OnEvent:  func(Event) {},
	})
	if _, err := eng2.Run(ctx, targetIP); err != nil {
		t.Fatalf("run 2: %v", err)
	}

	// The second run must have seen the first run's probe output in its
	// initial user prompt.
	hist := model2.lastHistory()
	if len(hist) == 0 {
		t.Fatal("run 2 model saw empty history")
	}
	prompt := hist[0].Content
	if !strings.Contains(prompt, "PRIOR FINDINGS ON THIS TARGET") {
		t.Errorf("run 2 prompt missing PRIOR FINDINGS section: %q", trim(prompt))
	}
	if !strings.Contains(prompt, "NUCLIDE-CANARY-7F3") {
		t.Errorf("run 2 prompt did not surface run 1 probe banner. Prompt:\n%s", prompt)
	}
	if !strings.Contains(prompt, "tool=probe") {
		t.Errorf("run 2 prompt missing tool metadata: %q", trim(prompt))
	}
}

// TestEphemeralModeDoesNotPersist: when StateDir is empty, AddFinding is a
// no-op and a second engine reads zero findings.
func TestEphemeralModeDoesNotPersist(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	probe := &fakeTool{name: "probe", desc: "x", schema: `{"target":"<host>"}`,
		handler: func(string) (string, error) { return "ephemeral-output", nil }}

	model := newFakeModel("eph",
		&Response{ToolCalls: []ToolCall{{ID: "tu_e", Name: "probe", Input: `{}`}}},
		&Response{Text: "done", StopReason: "end_turn"},
	)
	reg := tools.NewEmpty()
	reg.Register(probe)

	eph := mustRAG(t) // no state dir
	if eph.HasPersistence() {
		t.Fatalf("expected ephemeral engine to have no persistence")
	}

	eng := New(Config{Model: model, RAG: eph, Tools: reg, MaxSteps: 3, OnEvent: func(Event) {}})
	if _, err := eng.Run(ctx, "x"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := eph.FindingsCount(); got != 0 {
		t.Errorf("ephemeral findings count = %d, want 0", got)
	}
}

// ------------- tiny helpers -------------

func trim(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

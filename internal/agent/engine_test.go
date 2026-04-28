package agent

import (
	"context"
	"encoding/json"
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
	// Tool list is now transmitted via function-calling, not in user prompt.
	// The verbose "TOOLS AVAILABLE" manifest must NOT appear here anymore.
	if strings.Contains(prompt, "TOOLS AVAILABLE") {
		t.Errorf("user prompt still contains TOOLS AVAILABLE manifest — should be dropped (tools transmitted via function-calling)")
	}
}

// TestPromptIsTrimmed: with 4 retrieved playbook hits, the user prompt
// should NOT contain the full content of any retrieved chunk. The trim
// reduces per-turn token usage so a multi-step run fits inside Groq's
// free-tier 12k TPM ceiling.
func TestPromptIsTrimmed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	model := newFakeModel("trim", &Response{Text: "ok", StopReason: "end_turn"})
	eng := New(Config{
		Model:    model,
		RAG:      mustRAG(t),
		Tools:    tools.NewEmpty(),
		MaxSteps: 1,
		OnEvent:  func(Event) {},
	})
	if _, err := eng.Run(ctx, "aws ec2 cloud target"); err != nil {
		t.Fatalf("run: %v", err)
	}

	prompt := model.lastHistory()[0].Content

	// Sanity: prompt structure intact.
	if !strings.Contains(prompt, "playbook one-liners") {
		t.Errorf("expected one-liner header in prompt, got: %q", prompt[:min(300, len(prompt))])
	}

	// Pull the actual hits separately and confirm none of their FULL content
	// appears verbatim in the prompt — only the summarized first line.
	rg, _ := mustRAGUntyped(t)
	hits, err := rg.Search(ctx, "aws ec2 cloud target recon enumeration playbook", 4)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	for _, h := range hits {
		// If the chunk has multiple lines and is longer than the summary cap,
		// the full content should NOT appear verbatim.
		if strings.Count(h.Content, "\n") < 2 || len(h.Content) <= 200 {
			continue // chunk is already short; no leakage to detect
		}
		if strings.Contains(prompt, h.Content) {
			t.Errorf("full chunk leaked into trimmed prompt: %s :: %s", h.Source, h.Section)
		}
	}

	// Hard ceiling sanity: with 4 hits and no prior findings, the body of
	// the prompt should be well under 1500 chars (~375 tokens).
	if len(prompt) > 1500 {
		t.Errorf("trimmed prompt is %d chars, expected <1500", len(prompt))
	}
}

// TestSummarizeChunk: covers the edge cases of the one-line summarizer.
func TestSummarizeChunk(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		in    string
		max   int
		want  string
	}{
		{"plain first line", "First sentence here.\nSecond sentence.", 100, "First sentence here."},
		{"strips bullet", "- bullet item one\n- bullet item two", 100, "bullet item one"},
		{"strips numbered", "1. step one\n2. step two", 100, "step one"},
		{"truncates long", strings.Repeat("a", 250), 100, strings.Repeat("a", 100) + "…"},
		{"skips blank", "\n\n   \nactual content here", 100, "actual content here"},
		{"empty input", "", 100, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := summarizeChunk(tc.in, tc.max)
			if got != tc.want {
				t.Errorf("summarizeChunk(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
			}
		})
	}
}

// mustRAGUntyped returns the RAG engine + nil error for use in helper
// chains where we want a separate engine instance.
func mustRAGUntyped(t *testing.T) (*rag.Engine, error) {
	t.Helper()
	r, err := rag.NewWithEmbedder(context.Background(), fakeEmbedder, "fake-bag-of-words")
	return r, err
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

// TestManualGateRejectionPivots: when the Approver rejects a tool call,
// the tool must NOT execute; the rejection reason must be threaded back
// to the model as the observation so the agent can pivot.
func TestManualGateRejectionPivots(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	probe := &fakeTool{name: "probe", desc: "x", schema: `{"target":"<host>"}`,
		handler: func(string) (string, error) { return "should-never-run", nil }}

	model := newFakeModel("rejected",
		&Response{ToolCalls: []ToolCall{{ID: "tu_r", Name: "probe", Input: `{"target":"x"}`}}},
		&Response{Text: "summary: pivoted per operator", StopReason: "end_turn"},
	)
	reg := tools.NewEmpty()
	reg.Register(probe)

	const reason = "scan too heavy, try lighter alternative"
	rejector := func(_ context.Context, _ ApprovalRequest) (ApprovalDecision, error) {
		return ApprovalDecision{Approved: false, Reason: reason}, nil
	}

	cap := &capturedEvents{}
	eng := New(Config{
		Model:    model,
		RAG:      mustRAG(t),
		Tools:    reg,
		MaxSteps: 4,
		Approve:  rejector,
		OnEvent:  cap.on,
	})
	if _, err := eng.Run(ctx, "x"); err != nil {
		t.Fatalf("run: %v", err)
	}

	if probe.callCount != 0 {
		t.Errorf("rejected probe ran anyway: callCount=%d", probe.callCount)
	}

	// The model's second-call history must contain the rejection text.
	hist := model.lastHistory()
	if len(hist) < 3 {
		t.Fatalf("expected ≥3 history entries on second call, got %d", len(hist))
	}
	toolMsg := hist[len(hist)-1]
	if toolMsg.Role != RoleTool {
		t.Errorf("expected last history entry to be tool result, got role=%v", toolMsg.Role)
	}
	if !strings.Contains(toolMsg.Content, "User rejected") {
		t.Errorf("tool message missing rejection marker: %q", toolMsg.Content)
	}
	if !strings.Contains(toolMsg.Content, reason) {
		t.Errorf("rejection reason not threaded to model: %q", toolMsg.Content)
	}

	// Observe event should also carry the rejection.
	var observed string
	for _, e := range cap.ev {
		if e.Type == "observe" {
			observed = e.Result
		}
	}
	if !strings.Contains(observed, reason) {
		t.Errorf("observe event missing rejection reason: %q", observed)
	}
}

// TestManualGateApprovalRunsTool: happy-path — Approver returns true,
// tool runs as normal, output threads back through history.
func TestManualGateApprovalRunsTool(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	probe := &fakeTool{name: "probe", desc: "x", schema: `{"target":"<host>"}`,
		handler: func(string) (string, error) { return "approved-output-7K", nil }}

	model := newFakeModel("approved",
		&Response{ToolCalls: []ToolCall{{ID: "tu_a", Name: "probe", Input: `{"target":"x"}`}}},
		&Response{Text: "summary: clean run", StopReason: "end_turn"},
	)
	reg := tools.NewEmpty()
	reg.Register(probe)

	approver := func(_ context.Context, _ ApprovalRequest) (ApprovalDecision, error) {
		return ApprovalDecision{Approved: true}, nil
	}

	eng := New(Config{
		Model:    model,
		RAG:      mustRAG(t),
		Tools:    reg,
		MaxSteps: 4,
		Approve:  approver,
		OnEvent:  func(Event) {},
	})
	if _, err := eng.Run(ctx, "x"); err != nil {
		t.Fatalf("run: %v", err)
	}

	if probe.callCount != 1 {
		t.Errorf("approved probe should run exactly once, got callCount=%d", probe.callCount)
	}
	hist := model.lastHistory()
	toolMsg := hist[len(hist)-1]
	if !strings.Contains(toolMsg.Content, "approved-output-7K") {
		t.Errorf("tool output not threaded: %q", toolMsg.Content)
	}
}

// TestManualGateRejectedFindingPersisted: a rejected call should still
// appear in the persistent findings collection with status=rejected so
// future runs see "I tried this, the operator said no, with reason X".
func TestManualGateRejectedFindingPersisted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	stateDir := t.TempDir()
	const targetIP = "192.0.2.99"

	probe := &fakeTool{name: "probe", desc: "x", schema: `{"target":"<host>"}`,
		handler: func(string) (string, error) { return "never", nil }}

	model := newFakeModel("rejpersist",
		&Response{ToolCalls: []ToolCall{{ID: "tu_p", Name: "probe", Input: `{"target":"192.0.2.99"}`}}},
		&Response{Text: "ack", StopReason: "end_turn"},
	)
	reg := tools.NewEmpty()
	reg.Register(probe)

	rejector := func(_ context.Context, _ ApprovalRequest) (ApprovalDecision, error) {
		return ApprovalDecision{Approved: false, Reason: "DENIED-MARKER-9X"}, nil
	}

	eng := New(Config{
		Model:    model,
		RAG:      mustPersistentRAG(t, stateDir),
		Tools:    reg,
		MaxSteps: 3,
		Approve:  rejector,
		OnEvent:  func(Event) {},
	})
	if _, err := eng.Run(ctx, targetIP); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Re-open the engine; verify the rejected finding is queryable.
	rag2 := mustPersistentRAG(t, stateDir)
	prior, err := rag2.FindingsForTarget(ctx, targetIP, 5)
	if err != nil {
		t.Fatalf("findings query: %v", err)
	}
	if len(prior) == 0 {
		t.Fatalf("rejected finding not persisted")
	}
	var sawRejected bool
	for _, f := range prior {
		if f.Status == "rejected" && strings.Contains(f.Output, "DENIED-MARKER-9X") {
			sawRejected = true
		}
	}
	if !sawRejected {
		t.Errorf("no persisted finding with status=rejected and rejection reason: %+v", prior)
	}
}

// TestHasMeaningfulObservations: cortex should skip empty-result runs
// to avoid confabulated artifacts. Surfaced from run #17 against
// 185.116.97.167 (fully remediated post-disclosure) — model invented
// "violations" like "Assumes right to remain unexposed" when fed an
// empty visorgraph graph and an empty aimap port list.
func TestHasMeaningfulObservations(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hist []Message
		want bool
	}{
		{"empty history", nil, false},
		{"only errors", []Message{{Role: RoleTool, Content: "ERROR: unknown tool"}}, false},
		{"only rejections", []Message{{Role: RoleTool, Content: "User rejected tool execution. Reason: fragile target"}}, false},
		{"empty visorgraph graph", []Message{{Role: RoleTool, Content: `{"nodes":{},"edges":{},"created_at":1.7e9}`}}, false},
		{"empty aimap report", []Message{{Role: RoleTool, Content: `{"open_ports":[],"services":null,"summary":{"open_ports":0}}`}}, false},
		{"real visorgraph hit", []Message{{Role: RoleTool, Content: `{"nodes":{"x":{"type":"service","attrs":{"port":80,"http_status":200}}}}`}}, true},
		{"real aimap hit", []Message{{Role: RoleTool, Content: `{"open_ports":[{"host":"x","port":80,"open":true,"server":"Apache"}]}`}}, true},
		{"BARE ranking output", []Message{{Role: RoleTool, Content: `{"findings":[{"matches":[{"rank":1,"category":"auxiliary"}]}]}`}}, true},
		{"mixed (one real among empty)", []Message{
			{Role: RoleTool, Content: `{"nodes":{},"edges":{}}`},
			{Role: RoleTool, Content: `{"open_ports":[{"port":80,"server":"nginx"}]}`},
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasMeaningfulObservations(tc.hist); got != tc.want {
				t.Errorf("hasMeaningfulObservations(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestRAGSearchSurfacesAIOSINT: AI/ML-specific queries should surface
// chunks from the AI-LLM-OSINT catalogue embedded under playbooks/ai-osint/.
// Confirms (a) the embed pattern actually picked up the subdir,
// (b) retrieval reaches the new corpus, (c) playbook discovery is automatic.
func TestRAGSearchSurfacesAIOSINT(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	rg := mustRAG(t)
	if rg.Count() < 20 {
		t.Errorf("expected ≥20 chunks after AI-OSINT integration, got %d", rg.Count())
	}

	// AI-specific query should include at least one ai-osint source in
	// the top-8.
	hits, err := rg.Search(ctx, "vLLM model server inference endpoint exposed", 8)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	var sawAIOSINT bool
	for _, h := range hits {
		// embed.FS preserves the directory structure in the path metadata
		// recorded as 'source' — chunks from playbooks/ai-osint/ will have
		// the bare filename (e.g. "03-model-serving.md") since rag stores
		// just filepath.Base. We mark them implicitly: AI-OSINT files have
		// numeric-prefix or "ports"/"terminology" names that don't collide
		// with the 4 top-level playbooks.
		switch h.Source {
		case "ai-ml.md", "cloud.md", "web.md", "api.md":
			// top-level
		default:
			sawAIOSINT = true
		}
	}
	if !sawAIOSINT {
		var names []string
		for _, h := range hits {
			names = append(names, h.Source)
		}
		t.Errorf("AI-specific query didn't surface any AI-OSINT chunks; sources=%v", names)
	}
}

// TestRAGSearchDiversifiedAcrossSources: with 4 markdown playbooks in the
// corpus and k=4, the result must contain at least 4 distinct source files.
// Earlier the AI/ML playbook dominated the top-4 because of vocabulary
// overlap with the hardcoded retrieve query "recon enumeration playbook" —
// agent saw 2x ai-ml.md hits even when target was a plain web server.
func TestRAGSearchDiversifiedAcrossSources(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	rg := mustRAG(t)
	hits, err := rg.Search(ctx, "scanme.nmap.org recon enumeration playbook", 4)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) < 4 {
		t.Fatalf("expected 4 hits, got %d", len(hits))
	}
	sources := map[string]bool{}
	for _, h := range hits {
		sources[h.Source] = true
	}
	if len(sources) < 4 {
		t.Errorf("expected ≥4 distinct sources, got %d (%v)", len(sources), sources)
	}
}

// TestSchemaHintTypeInference: hint values with different JSON types must
// produce schemas with matching JSON-Schema types. A regression of the
// "everything is a string" bug bit us on the first live Groq run because
// llama-3.3 correctly emitted `top: 100` (number) but the schema declared
// `top: string`, causing strict server-side validation to reject the call.
func TestSchemaHintTypeInference(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		hint     string
		wantType map[string]string // property name → expected schema "type"
	}{
		{
			name:     "naabu hint with string + number",
			hint:     `{"target":"<ip|host>","top":100}`,
			wantType: map[string]string{"target": "string", "top": "integer"},
		},
		{
			name:     "nuclei hint with string array",
			hint:     `{"target":"<url>","tags":["exposure","cve"],"severity":"low,medium"}`,
			wantType: map[string]string{"target": "string", "tags": "array", "severity": "string"},
		},
		{
			name:     "boolean property",
			hint:     `{"target":"<host>","verbose":true}`,
			wantType: map[string]string{"target": "string", "verbose": "boolean"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := schemaHintToJSONSchema(tc.hint)
			var parsed struct {
				Type       string                            `json:"type"`
				Properties map[string]map[string]interface{} `json:"properties"`
				Required   []string                          `json:"required"`
			}
			if err := json.Unmarshal([]byte(got), &parsed); err != nil {
				t.Fatalf("invalid JSON: %v\n%s", err, got)
			}
			for prop, wantTy := range tc.wantType {
				p, ok := parsed.Properties[prop]
				if !ok {
					t.Errorf("property %q missing from schema: %s", prop, got)
					continue
				}
				if p["type"] != wantTy {
					t.Errorf("property %q type = %v, want %s", prop, p["type"], wantTy)
				}
			}
			// "target" should always be required.
			var hasTarget bool
			for _, r := range parsed.Required {
				if r == "target" {
					hasTarget = true
				}
			}
			if !hasTarget {
				t.Errorf("expected target in required list, got %v", parsed.Required)
			}
		})
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

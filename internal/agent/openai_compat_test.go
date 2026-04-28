package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestOpenAICompatRoundTrip drives the OpenAI-compat backend against a
// mock /chat/completions endpoint. Asserts:
//   - request shape (model, tools wrapped in {type:function, function:...},
//     tool_choice=auto when tools present)
//   - tool_calls in the response are parsed into ToolCall slice
//   - tool result messages are encoded as {role:tool, tool_call_id, content}
//     on the next turn, matching the OpenAI spec
func TestOpenAICompatRoundTrip(t *testing.T) {
	// Cannot t.Parallel() — uses t.Setenv.

	var (
		mu       sync.Mutex
		callIdx  int
		captured []map[string]any
	)

	canned := []map[string]any{
		// Turn 1: model emits a tool call.
		{
			"choices": []map[string]any{{
				"finish_reason": "tool_calls",
				"message": map[string]any{
					"content": "",
					"tool_calls": []map[string]any{{
						"id":   "call_abc",
						"type": "function",
						"function": map[string]any{
							"name":      "httpx",
							"arguments": `{"target":"192.0.2.1"}`,
						},
					}},
				},
			}},
		},
		// Turn 2: model emits a final summary, no tool calls.
		{
			"choices": []map[string]any{{
				"finish_reason": "stop",
				"message": map[string]any{
					"content":    "summary: probe completed",
					"tool_calls": nil,
				},
			}},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization header = %q, want Bearer test-key", got)
		}
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		_ = json.Unmarshal(body, &parsed)

		mu.Lock()
		captured = append(captured, parsed)
		idx := callIdx
		callIdx++
		mu.Unlock()

		if idx >= len(canned) {
			t.Errorf("unexpected %dth call", idx+1)
			http.Error(w, "no more canned responses", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(canned[idx])
	}))
	defer srv.Close()

	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OPENAI_BASE_URL", srv.URL)
	t.Setenv("VISORRAG_MODEL", "test-model-x")

	model, err := NewOpenAICompat()
	if err != nil {
		t.Fatalf("NewOpenAICompat: %v", err)
	}
	if model.Name() != "openai:test-model-x" {
		t.Errorf("Name() = %q, want openai:test-model-x", model.Name())
	}

	// Turn 1: get the tool call.
	resp, err := model.Generate(context.Background(), "you are a test", nil, []ToolSpec{
		{Name: "httpx", Description: "probe http", JSONSchema: `{"type":"object"}`},
	})
	if err != nil {
		t.Fatalf("Generate turn 1: %v", err)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(resp.ToolCalls))
	}
	tc := resp.ToolCalls[0]
	if tc.ID != "call_abc" || tc.Name != "httpx" {
		t.Errorf("tool call mis-parsed: %+v", tc)
	}
	if !strings.Contains(tc.Input, "192.0.2.1") {
		t.Errorf("tool input lost: %q", tc.Input)
	}

	// Turn 2: send the tool result back, expect final.
	hist := []Message{
		{Role: RoleUser, Content: "scan it"},
		{Role: RoleAssistant, ToolCalls: resp.ToolCalls},
		{Role: RoleTool, ToolUseID: "call_abc", Content: "ok 8080"},
	}
	resp2, err := model.Generate(context.Background(), "you are a test", hist, nil)
	if err != nil {
		t.Fatalf("Generate turn 2: %v", err)
	}
	if !strings.Contains(resp2.Text, "probe completed") {
		t.Errorf("final text mis-parsed: %q", resp2.Text)
	}
	if len(resp2.ToolCalls) != 0 {
		t.Errorf("expected zero tool calls on final, got %d", len(resp2.ToolCalls))
	}

	// Inspect captured request bodies.
	if len(captured) != 2 {
		t.Fatalf("expected 2 captured requests, got %d", len(captured))
	}

	// Turn 1 request: tools + tool_choice present, model + system message correct.
	r1 := captured[0]
	if r1["model"] != "test-model-x" {
		t.Errorf("turn 1 model = %v, want test-model-x", r1["model"])
	}
	if r1["tool_choice"] != "auto" {
		t.Errorf("turn 1 tool_choice = %v, want auto", r1["tool_choice"])
	}
	tools, ok := r1["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("turn 1 tools mis-shaped: %v", r1["tools"])
	}
	tool0 := tools[0].(map[string]any)
	if tool0["type"] != "function" {
		t.Errorf("tool type = %v, want function", tool0["type"])
	}
	fn := tool0["function"].(map[string]any)
	if fn["name"] != "httpx" {
		t.Errorf("tool name = %v, want httpx", fn["name"])
	}

	// Turn 2 request: tool result encoded with role=tool + tool_call_id.
	r2 := captured[1]
	msgs := r2["messages"].([]any)
	if len(msgs) < 4 { // system + user + assistant + tool
		t.Fatalf("turn 2 messages too short: %v", msgs)
	}
	last := msgs[len(msgs)-1].(map[string]any)
	if last["role"] != "tool" {
		t.Errorf("last message role = %v, want tool", last["role"])
	}
	if last["tool_call_id"] != "call_abc" {
		t.Errorf("tool_call_id mis-threaded: %v", last["tool_call_id"])
	}
	if !strings.Contains(last["content"].(string), "ok 8080") {
		t.Errorf("tool result content lost: %v", last["content"])
	}
}

// TestOpenAICompatGroqPreset verifies the GROQ_API_KEY branch resolves
// to the Groq endpoint and a sensible default model.
func TestOpenAICompatGroqPreset(t *testing.T) {
	// Cannot run in parallel — env mutation.
	t.Setenv("GROQ_API_KEY", "gsk_test")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("VISORRAG_MODEL", "")
	t.Setenv("OPENAI_BASE_URL", "")

	m, err := NewOpenAICompat()
	if err != nil {
		t.Fatalf("NewOpenAICompat: %v", err)
	}
	if !strings.HasPrefix(m.endpoint, "https://api.groq.com") {
		t.Errorf("groq preset endpoint wrong: %s", m.endpoint)
	}
	if !strings.Contains(m.model, "llama") {
		t.Errorf("groq default model not llama-family: %s", m.model)
	}
	if !strings.HasPrefix(m.label, "groq:") {
		t.Errorf("groq label prefix wrong: %s", m.label)
	}
}

// TestPickModelGroqRouting verifies PickModel routes to OpenAICompat
// when only GROQ_API_KEY is set.
func TestPickModelGroqRouting(t *testing.T) {
	t.Setenv("VISORRAG_LLM", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("GROQ_API_KEY", "gsk_test")
	t.Setenv("OPENAI_API_KEY", "")

	m, err := PickModel()
	if err != nil {
		t.Fatalf("PickModel: %v", err)
	}
	if !strings.HasPrefix(m.Name(), "groq:") {
		t.Errorf("PickModel returned %s, want groq:* model", m.Name())
	}
}

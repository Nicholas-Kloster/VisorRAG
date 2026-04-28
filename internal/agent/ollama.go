package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// OllamaModel uses Ollama's /api/chat with native tool-call support
// (Ollama 0.4+). For older Ollama, the model can still respond with text
// describing tool intent; the agent loop will handle missing structured
// tool_calls gracefully.
type OllamaModel struct {
	endpoint string
	model    string
	hc       *http.Client
}

func NewOllama() (*OllamaModel, error) {
	host := os.Getenv("OLLAMA_HOST")
	if host == "" {
		host = "http://localhost:11434"
	}
	if !strings.HasPrefix(host, "http") {
		host = "http://" + host
	}
	model := os.Getenv("VISORRAG_MODEL")
	if model == "" {
		model = "llama3.1"
	}
	return &OllamaModel{
		endpoint: strings.TrimSuffix(host, "/"),
		model:    model,
		hc:       &http.Client{Timeout: 5 * time.Minute},
	}, nil
}

func (o *OllamaModel) Name() string { return "ollama:" + o.model }

func (o *OllamaModel) Generate(ctx context.Context, system string, history []Message, tools []ToolSpec) (*Response, error) {
	msgs := []map[string]any{}
	if system != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": system})
	}
	for _, m := range history {
		switch m.Role {
		case RoleUser:
			msgs = append(msgs, map[string]any{"role": "user", "content": m.Content})
		case RoleAssistant:
			entry := map[string]any{"role": "assistant", "content": m.Content}
			if len(m.ToolCalls) > 0 {
				calls := make([]map[string]any, 0, len(m.ToolCalls))
				for _, tc := range m.ToolCalls {
					var input any
					_ = json.Unmarshal([]byte(tc.Input), &input)
					calls = append(calls, map[string]any{
						"function": map[string]any{
							"name":      tc.Name,
							"arguments": input,
						},
					})
				}
				entry["tool_calls"] = calls
			}
			msgs = append(msgs, entry)
		case RoleTool:
			msgs = append(msgs, map[string]any{
				"role":    "tool",
				"content": m.Content,
				// Ollama doesn't require tool_use_id but include for symmetry.
				"name": m.ToolUseID,
			})
		}
	}

	body := map[string]any{
		"model":    o.model,
		"messages": msgs,
		"stream":   false,
	}
	if len(tools) > 0 {
		body["tools"] = ollamaTools(tools)
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", o.endpoint+"/api/chat", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := o.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ollama %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed struct {
		Message struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Function struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		DoneReason string `json:"done_reason"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("decode ollama response: %w", err)
	}

	out := &Response{
		Text:       parsed.Message.Content,
		StopReason: parsed.DoneReason,
	}
	for i, c := range parsed.Message.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, ToolCall{
			ID:    fmt.Sprintf("call_%d", i),
			Name:  c.Function.Name,
			Input: string(c.Function.Arguments),
		})
	}
	return out, nil
}

func ollamaTools(tools []ToolSpec) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		var schema any
		if err := json.Unmarshal([]byte(t.JSONSchema), &schema); err != nil {
			schema = map[string]any{"type": "object", "additionalProperties": true}
		}
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  schema,
			},
		})
	}
	return out
}

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

// AnthropicModel speaks Messages API directly over HTTP. We avoid the
// official SDK because it requires Go 1.23+ and we want a portable
// single-binary build. The Messages API surface used here is stable.
type AnthropicModel struct {
	apiKey    string
	model     string
	endpoint  string
	maxTokens int
	hc        *http.Client
}

func NewAnthropic() (*AnthropicModel, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}
	model := os.Getenv("VISORRAG_MODEL")
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	ep := os.Getenv("ANTHROPIC_BASE_URL")
	if ep == "" {
		ep = "https://api.anthropic.com"
	}
	return &AnthropicModel{
		apiKey:    key,
		model:     model,
		endpoint:  strings.TrimSuffix(ep, "/"),
		maxTokens: 4096,
		hc:        &http.Client{Timeout: llmTimeout(2 * time.Minute)},
	}, nil
}

// llmTimeout reads VISORRAG_LLM_TIMEOUT (Go duration) or returns the default.
func llmTimeout(def time.Duration) time.Duration {
	if v := os.Getenv("VISORRAG_LLM_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func (a *AnthropicModel) Name() string { return "anthropic:" + a.model }

func (a *AnthropicModel) Generate(ctx context.Context, system string, history []Message, tools []ToolSpec) (*Response, error) {
	body := map[string]any{
		"model":      a.model,
		"max_tokens": a.maxTokens,
		"messages":   anthropicMessages(history),
	}
	if system != "" {
		body["system"] = system
	}
	if len(tools) > 0 {
		body["tools"] = anthropicTools(tools)
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", a.endpoint+"/v1/messages", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("decode anthropic response: %w", err)
	}

	out := &Response{StopReason: parsed.StopReason}
	for _, c := range parsed.Content {
		switch c.Type {
		case "text":
			out.Text += c.Text
		case "tool_use":
			out.ToolCalls = append(out.ToolCalls, ToolCall{
				ID:    c.ID,
				Name:  c.Name,
				Input: string(c.Input),
			})
		}
	}
	return out, nil
}

func anthropicMessages(history []Message) []map[string]any {
	out := make([]map[string]any, 0, len(history))
	for _, m := range history {
		switch m.Role {
		case RoleUser:
			out = append(out, map[string]any{"role": "user", "content": m.Content})
		case RoleAssistant:
			if len(m.ToolCalls) == 0 {
				out = append(out, map[string]any{"role": "assistant", "content": m.Content})
				continue
			}
			content := []map[string]any{}
			if m.Content != "" {
				content = append(content, map[string]any{"type": "text", "text": m.Content})
			}
			for _, tc := range m.ToolCalls {
				var input any
				_ = json.Unmarshal([]byte(tc.Input), &input)
				content = append(content, map[string]any{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Name,
					"input": input,
				})
			}
			out = append(out, map[string]any{"role": "assistant", "content": content})
		case RoleTool:
			// Tool results are sent as a user-role message with tool_result blocks.
			out = append(out, map[string]any{
				"role": "user",
				"content": []map[string]any{
					{"type": "tool_result", "tool_use_id": m.ToolUseID, "content": m.Content},
				},
			})
		}
	}
	return out
}

func anthropicTools(tools []ToolSpec) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		var schema any
		if err := json.Unmarshal([]byte(t.JSONSchema), &schema); err != nil {
			// Fall back to a permissive schema so a malformed adapter
			// doesn't break the whole run.
			schema = map[string]any{
				"type":                 "object",
				"additionalProperties": true,
			}
		}
		out = append(out, map[string]any{
			"name":         t.Name,
			"description":  t.Description,
			"input_schema": schema,
		})
	}
	return out
}

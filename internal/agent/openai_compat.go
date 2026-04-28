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

// OpenAICompatModel speaks the OpenAI /v1/chat/completions surface, which
// is supported by OpenAI itself and by every major drop-in compat provider:
// Groq, OpenRouter, Together, Fireworks, Cerebras, Anyscale, Hyperbolic,
// plus self-hosted options (vLLM, llama.cpp server, Ollama's /v1 surface).
//
// One backend, dozens of providers. Provider selection is by env var:
//
//   - GROQ_API_KEY set        → Groq (preset URL + default model)
//   - OPENAI_API_KEY set      → OpenAI (or any compat with OPENAI_BASE_URL)
//
// Override the model with VISORRAG_MODEL. Override the endpoint for a
// generic compat provider with OPENAI_BASE_URL.
type OpenAICompatModel struct {
	apiKey    string
	model     string
	endpoint  string
	maxTokens int
	label     string
	hc        *http.Client
}

func NewOpenAICompat() (*OpenAICompatModel, error) {
	var (
		apiKey, endpoint, defaultModel, providerLabel string
	)

	switch {
	case os.Getenv("GROQ_API_KEY") != "":
		apiKey = os.Getenv("GROQ_API_KEY")
		endpoint = envOr("OPENAI_BASE_URL", "https://api.groq.com/openai/v1")
		defaultModel = "llama-3.3-70b-versatile"
		providerLabel = "groq"
	case os.Getenv("OPENAI_API_KEY") != "":
		apiKey = os.Getenv("OPENAI_API_KEY")
		endpoint = envOr("OPENAI_BASE_URL", "https://api.openai.com/v1")
		defaultModel = "gpt-4o-mini"
		providerLabel = "openai"
	default:
		return nil, fmt.Errorf("no OpenAI-compatible API key set (GROQ_API_KEY or OPENAI_API_KEY)")
	}

	model := envOr("VISORRAG_MODEL", defaultModel)

	return &OpenAICompatModel{
		apiKey:    apiKey,
		model:     model,
		endpoint:  strings.TrimSuffix(endpoint, "/"),
		maxTokens: 4096,
		label:     fmt.Sprintf("%s:%s", providerLabel, model),
		hc:        &http.Client{Timeout: llmTimeout(2 * time.Minute)},
	}, nil
}

func (m *OpenAICompatModel) Name() string { return m.label }

func (m *OpenAICompatModel) Generate(ctx context.Context, system string, history []Message, tools []ToolSpec) (*Response, error) {
	msgs := make([]map[string]any, 0, len(history)+1)
	if system != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": system})
	}
	for _, h := range history {
		switch h.Role {
		case RoleUser:
			msgs = append(msgs, map[string]any{"role": "user", "content": h.Content})
		case RoleAssistant:
			entry := map[string]any{"role": "assistant"}
			if h.Content != "" {
				entry["content"] = h.Content
			}
			if len(h.ToolCalls) > 0 {
				tc := make([]map[string]any, 0, len(h.ToolCalls))
				for _, c := range h.ToolCalls {
					tc = append(tc, map[string]any{
						"id":   c.ID,
						"type": "function",
						"function": map[string]any{
							"name":      c.Name,
							"arguments": c.Input, // already a JSON string per OpenAI spec
						},
					})
				}
				entry["tool_calls"] = tc
			}
			msgs = append(msgs, entry)
		case RoleTool:
			msgs = append(msgs, map[string]any{
				"role":         "tool",
				"tool_call_id": h.ToolUseID,
				"content":      h.Content,
			})
		}
	}

	body := map[string]any{
		"model":      m.model,
		"messages":   msgs,
		"max_tokens": m.maxTokens,
	}
	if len(tools) > 0 {
		body["tools"] = openaiCompatTools(tools)
		body["tool_choice"] = "auto"
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", m.endpoint+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer "+m.apiKey)

	resp, err := m.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai-compat request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("openai-compat %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("openai-compat: no choices in response: %s", string(respBody))
	}
	ch := parsed.Choices[0]

	out := &Response{
		Text:       ch.Message.Content,
		StopReason: ch.FinishReason,
	}
	for _, tc := range ch.Message.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, ToolCall{
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: tc.Function.Arguments,
		})
	}
	return out, nil
}

func openaiCompatTools(tools []ToolSpec) []map[string]any {
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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

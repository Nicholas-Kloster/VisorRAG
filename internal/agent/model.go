// Package agent contains the ReAct loop, model interface, and provider
// implementations.
//
// Design note: the brief called for the Eino framework. We instead implement
// a direct ReAct loop because (a) Anthropic's Go SDK has first-class tool-use
// support that subsumes the Eino compose graph value-add for our scope, and
// (b) the Nuclide protocol prefers single-binary / minimal-deps. The Model
// interface below is the seam where Eino (or any other framework) could be
// plugged in if the project grows.
package agent

import "context"

// Role is a chat-message role.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// Message is a single chat-history entry the model sees.
//
//   - RoleAssistant + ToolCalls   = the model wants to invoke tools
//   - RoleTool      + ToolUseID   = the result of that tool, fed back
//   - RoleSystem/User/Assistant   = plain text, Content set
type Message struct {
	Role      Role
	Content   string
	ToolCalls []ToolCall // assistant turn requesting tools
	ToolUseID string     // tool turn answering a specific call
}

// ToolCall is the model's structured request to invoke a tool.
type ToolCall struct {
	ID    string // provider-assigned, must round-trip on the tool-result message
	Name  string
	Input string // JSON-encoded args
}

// ToolSpec is what we advertise to the model.
type ToolSpec struct {
	Name        string
	Description string
	// JSONSchema is the input schema, encoded as a JSON string. Providers
	// vary on whether they want a parsed object or raw bytes; we keep it
	// raw and let each adapter unmarshal.
	JSONSchema string
}

// Response is one assistant turn — either text, tool calls, or both.
type Response struct {
	Text      string
	ToolCalls []ToolCall
	StopReason string
}

// Model abstracts the LLM provider. One Generate call = one assistant turn.
type Model interface {
	Generate(ctx context.Context, system string, history []Message, tools []ToolSpec) (*Response, error)
	Name() string
}

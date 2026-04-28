package agent

import (
	"context"
	"fmt"
	"sync"
)

// fakeModel is a scripted Model implementation used by engine tests.
// Each call to Generate pops the next response off the script. Captured
// inputs (system prompt, history, advertised tools) are retained per-call
// so tests can assert on them.
type fakeModel struct {
	mu       sync.Mutex
	name     string
	script   []*Response

	calls    int
	gotSys   []string
	gotHist  [][]Message
	gotTools [][]ToolSpec
}

func newFakeModel(name string, script ...*Response) *fakeModel {
	return &fakeModel{name: name, script: script}
}

func (f *fakeModel) Name() string { return "fake:" + f.name }

func (f *fakeModel) Generate(_ context.Context, system string, history []Message, tools []ToolSpec) (*Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.gotSys = append(f.gotSys, system)
	histCopy := make([]Message, len(history))
	copy(histCopy, history)
	f.gotHist = append(f.gotHist, histCopy)
	toolsCopy := make([]ToolSpec, len(tools))
	copy(toolsCopy, tools)
	f.gotTools = append(f.gotTools, toolsCopy)

	if f.calls >= len(f.script) {
		return nil, fmt.Errorf("fakeModel: script exhausted at call %d (had %d responses)", f.calls+1, len(f.script))
	}
	r := f.script[f.calls]
	f.calls++
	return r, nil
}

func (f *fakeModel) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// lastHistory returns the history snapshot the model saw on its most
// recent Generate call. Useful for asserting tool-result threading.
func (f *fakeModel) lastHistory() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.gotHist) == 0 {
		return nil
	}
	return f.gotHist[len(f.gotHist)-1]
}

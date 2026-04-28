package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CortexConfig controls the optional terminal step that drafts a Cortex
// authorization-context artifact (SKELETON / VIOLATIONS / CONTEXT) from
// the run's findings and runs analyzer.py to produce structured outputs.
//
// Cortex is post-recon analysis, not a probe — it does not need the gVisor
// sandbox, runs on the host, and only reads the run's own history.
type CortexConfig struct {
	// Enabled gates the entire postprocessor. Off by default.
	Enabled bool

	// FrameworkPath is the path to a cortex-framework checkout (the dir
	// containing analyzer.py, framework.md, examples/). If empty,
	// $VISORRAG_CORTEX_DIR is consulted, then ~/cortex-framework.
	FrameworkPath string

	// OutputDir is where artifacts land. Empty → <state-dir>/cortex/.
	OutputDir string
}

// Resolve fills in defaults using env + state-dir. Idempotent — safe to
// call again with the same args.
func (c *CortexConfig) Resolve(stateDir string) error {
	if c.FrameworkPath == "" {
		if env := os.Getenv("VISORRAG_CORTEX_DIR"); env != "" {
			c.FrameworkPath = env
		} else if home, err := os.UserHomeDir(); err == nil {
			c.FrameworkPath = filepath.Join(home, "cortex-framework")
		}
	}
	if _, err := os.Stat(filepath.Join(c.FrameworkPath, "analyzer.py")); err != nil {
		return fmt.Errorf("cortex-framework analyzer.py not found at %s: %w", c.FrameworkPath, err)
	}
	if c.OutputDir == "" {
		base := stateDir
		if base == "" {
			base = filepath.Join(os.TempDir(), "visor-rag-cortex")
		}
		c.OutputDir = filepath.Join(base, "cortex")
	}
	return os.MkdirAll(c.OutputDir, 0o755)
}

// generateCortexArtifact is called after the ReAct loop terminates. It
// asks the LLM to draft a Cortex-format markdown describing the target's
// authorization context, writes it to disk, and runs analyzer.py to
// produce structured JSON + report outputs.
func (e *Engine) generateCortexArtifact(ctx context.Context, target, runID string, history []Message) error {
	if !e.cortex.Enabled {
		return nil
	}

	// If the run produced no successful observations (target unresponsive,
	// firewalled, fully remediated), skip the analysis. Earlier behavior
	// asked the LLM to draft an artifact from empty input, which produced
	// confabulated "violations" like "assumes right to remain unexposed"
	// — nonsense for a target with no exposed surface.
	if !hasMeaningfulObservations(history) {
		e.emit(Event{
			Time:    time.Now(),
			Type:    "cortex",
			RunID:   runID,
			Message: "skipped — no meaningful observations to analyze (target appears unresponsive or fully remediated)",
		})
		return nil
	}

	// Load only the format example. Earlier we also sent framework.md but
	// at ~23KB it pushed CPU-bound local models past their HTTP timeout.
	// The format requirements in buildCortexSystemPrompt + one example are
	// enough to anchor the output. framework.md remains useful for
	// human readers; we just don't ship it to the model.
	examplePath := filepath.Join(e.cortex.FrameworkPath, "examples", "iloveyou.md")
	example, _ := os.ReadFile(examplePath) // best-effort

	system := buildCortexSystemPrompt(example)
	user := buildCortexUserPrompt(target, history)

	resp, err := e.model.Generate(ctx, system, []Message{{Role: RoleUser, Content: user}}, nil)
	if err != nil {
		return fmt.Errorf("draft cortex markdown: %w", err)
	}

	mdPath := filepath.Join(e.cortex.OutputDir, runID+".md")
	body := extractMarkdown(resp.Text)
	if err := os.WriteFile(mdPath, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write cortex md: %w", err)
	}

	outDir := filepath.Join(e.cortex.OutputDir, runID+"-out")
	cmd := exec.CommandContext(ctx, "python3",
		filepath.Join(e.cortex.FrameworkPath, "analyzer.py"),
		"-q",
		"analyze", mdPath,
		"--output-dir", outDir,
		"--force", // emit reports even if skeleton/violations parse imperfectly
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Surface analyzer errors but don't fail the whole run — the
		// drafted markdown is still on disk and useful as raw output.
		e.emit(Event{
			Time: time.Now(), Type: "error", RunID: runID,
			Message: fmt.Sprintf("cortex analyzer.py failed: %v\noutput: %s", err, string(out)),
		})
		e.emit(Event{
			Time: time.Now(), Type: "cortex", RunID: runID,
			Message: fmt.Sprintf("draft markdown saved (analyzer skipped due to error): %s", mdPath),
		})
		return nil
	}

	e.emit(Event{
		Time:    time.Now(),
		Type:    "cortex",
		RunID:   runID,
		Message: fmt.Sprintf("artifact: %s | structured outputs: %s", mdPath, outDir),
	})
	return nil
}

func buildCortexSystemPrompt(example []byte) string {
	var sb strings.Builder
	sb.WriteString(`You are drafting a Cortex authorization-context analysis for the
target of an authorized security reconnaissance engagement. Cortex
describes a system in three parts: what it does (operations are
neutral), what it took without asking (authorization violations), and
why those violations matter (context).

OUTPUT REQUIREMENTS:
- Three sections only: SKELETON, VIOLATIONS, CONTEXT.
- Each section: H2 heading (## SKELETON / ## VIOLATIONS / ## CONTEXT),
  then a bulleted list. Five to fifteen bullets per section.
- SKELETON: what the target's exposed services factually do — describe
  behavior without judgment. "Serves HTTP on port 80 via Apache 2.4.7."
- VIOLATIONS: authorization gaps the target's exposure assumes — what
  it's taking, exposing, or making available without explicit consent
  or appropriate scope. Phrase as "Assumes right to ..."
- CONTEXT: why each violation matters. Impact, blast radius, business
  risk, exposure-to-real-users.
- Output ONLY the markdown. Begin with an H1 title line. No preamble,
  no commentary, no fenced code blocks around the output.
`)

	if len(example) > 0 {
		sb.WriteString("\n--- REFERENCE EXAMPLE (for format only; your subject is different) ---\n\n")
		sb.Write(example)
	}

	return sb.String()
}

func buildCortexUserPrompt(target string, history []Message) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "TARGET: %s\n\nThe recon agent gathered these observations during the run:\n\n", target)
	for _, m := range history {
		switch m.Role {
		case RoleAssistant:
			for _, tc := range m.ToolCalls {
				fmt.Fprintf(&sb, "## Tool invocation: %s\nargs: %s\n\n", tc.Name, tc.Input)
			}
			if m.Content != "" {
				fmt.Fprintf(&sb, "## Agent reasoning\n%s\n\n", m.Content)
			}
		case RoleTool:
			fmt.Fprintf(&sb, "## Observation (tool_use_id=%s)\n%s\n\n", m.ToolUseID, truncate(m.Content, 2000))
		}
	}
	sb.WriteString("\nDraft the Cortex analysis now.")
	return sb.String()
}

// hasMeaningfulObservations returns true if the history contains at least
// one tool result that contains an exposure signal — a port, a server
// header, a title, an open-state flag, etc. Empty graphs (visorgraph
// returns {"nodes":{},"edges":{}} when nothing is exposed), aimap returns
// "no open ports", error strings, and rejection strings all fail this
// check, so Cortex skips the draft turn for genuinely-empty runs and
// avoids the confabulated "violations" we saw on run #17 (185.116.97.167,
// fully remediated post-disclosure).
//
// The indicator list is empirical for our current toolset (visorgraph,
// aimap, menlohunt, BARE). When new tools land, add their structural
// signal markers here.
func hasMeaningfulObservations(history []Message) bool {
	indicators := []string{
		`"open":true`, `"open": true`, // aimap open-port flag
		`"port":`,         // any tool reporting a port number in JSON
		`"server":`,       // HTTP server header from any HTTP probe
		`"title":`,        // HTTP page title
		`"http_status"`,   // visorgraph HTTP probe attrs
		`"service":`,      // visorgraph service classification
		`"exposure":`,     // visorgraph exposure tagging
		`"matches"`,       // BARE module rankings
		`"category":`,     // BARE module category
		`"banner":`,       // raw-protocol banner from menlohunt
		`"finding":`,      // menlohunt severity finding
		`"severity":`,     // anything with a severity field
		`"product":`,      // menlohunt product detection
		`"cert":`,         // TLS cert SAN material
	}
	for _, m := range history {
		if m.Role != RoleTool {
			continue
		}
		body := m.Content
		if strings.HasPrefix(strings.TrimSpace(body), "ERROR:") ||
			strings.HasPrefix(strings.TrimSpace(body), "User rejected") {
			continue
		}
		for _, ind := range indicators {
			if strings.Contains(body, ind) {
				return true
			}
		}
	}
	return false
}

// extractMarkdown strips fenced code blocks the LLM may have wrapped
// around the output despite the system prompt asking it not to.
func extractMarkdown(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// Drop the first line (```markdown or ```)
		if nl := strings.Index(s, "\n"); nl > 0 {
			s = s[nl+1:]
		}
		// Drop trailing fence
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
	}
	return strings.TrimSpace(s) + "\n"
}

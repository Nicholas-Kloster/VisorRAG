// Command visor is the VisorRAG CLI: agentic recon driven by a RAG-grounded
// LLM, with every probe sandboxed inside gVisor.
//
// Usage:
//
//	visor -target 192.0.2.1
//	visor -target example.com -max-steps 8
//	visor -target 10.0.0.0/24 -model claude-sonnet-4-6
//
// Provider selection is via env (see internal/agent/engine.go: PickModel).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Nicholas-Kloster/visor-rag/internal/agent"
	"github.com/Nicholas-Kloster/visor-rag/internal/rag"
	"github.com/Nicholas-Kloster/visor-rag/internal/sandbox"
	"github.com/Nicholas-Kloster/visor-rag/internal/tools"

	// Side-effect: register embedded playbooks with the RAG engine.
	_ "github.com/Nicholas-Kloster/visor-rag/playbooks"
)

func main() {
	var (
		target         string
		maxSteps       int
		sandboxTimeout time.Duration
		quiet          bool
		stateDir       string
		ephemeral      bool
		manual         bool
		cortex         bool
		cortexDir      string
	)

	root := &cobra.Command{
		Use:           "visor",
		Short:         "Agentic recon over a RAG-grounded LLM with gVisor-sandboxed probes",
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if !quiet {
				printBanner()
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return fmt.Errorf("--target is required")
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			exec, err := sandbox.New(sandboxTimeout)
			if err != nil {
				return fmt.Errorf("sandbox init: %w", err)
			}

			resolvedStateDir, err := resolveStateDir(stateDir, ephemeral)
			if err != nil {
				return err
			}
			ragEngine, err := rag.NewPersistent(ctx, resolvedStateDir)
			if err != nil {
				return fmt.Errorf("rag init: %w", err)
			}
			if ragEngine.HasPersistence() {
				fmt.Fprintf(os.Stderr, "visor: findings persisted at %s (count=%d)\n",
					ragEngine.FindingsDir(), ragEngine.FindingsCount())
			} else {
				fmt.Fprintln(os.Stderr, "visor: persistence disabled (--ephemeral); findings will not survive this run")
			}

			model, err := agent.PickModel()
			if err != nil {
				return fmt.Errorf("model init: %w", err)
			}

			reg := tools.NewRegistry(exec)

			enc := json.NewEncoder(os.Stdout)
			var approver agent.Approver
			if manual {
				approver = newStdinApprover(os.Stdin, os.Stderr)
				fmt.Fprintln(os.Stderr, "visor: --manual gate active. y=approve, n=reject, anything else=reject with that text as guidance to the agent.")
			}
			cortexCfg := agent.CortexConfig{Enabled: cortex, FrameworkPath: cortexDir}
			if cortex {
				if err := cortexCfg.Resolve(resolvedStateDir); err != nil {
					return fmt.Errorf("cortex: %w", err)
				}
				fmt.Fprintf(os.Stderr, "visor: cortex postprocessor enabled. framework=%s out=%s\n",
					cortexCfg.FrameworkPath, cortexCfg.OutputDir)
			}

			eng := agent.New(agent.Config{
				Model:    model,
				RAG:      ragEngine,
				Tools:    reg,
				MaxSteps: maxSteps,
				Approve:  approver,
				Cortex:   cortexCfg,
				OnEvent: func(e agent.Event) {
					if quiet && e.Type != "final" && e.Type != "error" && e.Type != "cortex" {
						return
					}
					_ = enc.Encode(e)
				},
			})

			summary, err := eng.Run(ctx, target)
			if err != nil {
				return err
			}
			if quiet {
				fmt.Fprintln(os.Stdout, summary)
			}
			return nil
		},
	}

	root.Flags().StringVar(&target, "target", "", "IP, CIDR, or domain to recon")
	root.Flags().IntVar(&maxSteps, "max-steps", 12, "agent step budget")
	root.Flags().DurationVar(&sandboxTimeout, "sandbox-timeout", 5*time.Minute, "per-probe sandbox timeout")
	root.Flags().BoolVar(&quiet, "quiet", false, "suppress per-step events; only emit final summary")
	root.Flags().StringVar(&stateDir, "state-dir", "", "directory for persisted findings (default ~/.visor-rag/state)")
	root.Flags().BoolVar(&ephemeral, "ephemeral", false, "disable findings persistence for this run")
	root.Flags().BoolVar(&manual, "manual", false, "interactively approve every tool invocation (y/n/<reason text>)")
	root.Flags().BoolVar(&cortex, "cortex", false, "after the recon loop, draft a Cortex authorization-context artifact and run analyzer.py")
	root.Flags().StringVar(&cortexDir, "cortex-dir", "", "path to cortex-framework checkout (default $VISORRAG_CORTEX_DIR or ~/cortex-framework)")

	// ---- recall subcommand ----
	var recallLimit int
	recall := &cobra.Command{
		Use:           "recall <target>",
		Short:         "Show prior findings persisted for a target (no LLM, no probes)",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			resolved, err := resolveStateDir(stateDir, false)
			if err != nil {
				return err
			}
			ragEngine, err := rag.NewPersistent(ctx, resolved)
			if err != nil {
				return fmt.Errorf("rag init: %w", err)
			}
			if !ragEngine.HasPersistence() {
				return fmt.Errorf("persistence layer not available at %s", resolved)
			}
			fmt.Fprintf(os.Stderr, "visor recall: store=%s total_findings=%d\n",
				ragEngine.FindingsDir(), ragEngine.FindingsCount())

			findings, err := ragEngine.FindingsForTarget(ctx, target, recallLimit)
			if err != nil {
				return fmt.Errorf("query: %w", err)
			}
			if len(findings) == 0 {
				fmt.Fprintf(os.Stderr, "no findings for %s\n", target)
				return nil
			}
			enc := json.NewEncoder(os.Stdout)
			for _, f := range findings {
				_ = enc.Encode(f)
			}
			return nil
		},
	}
	recall.Flags().IntVar(&recallLimit, "limit", 50, "max findings to return")
	root.AddCommand(recall)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "visor:", err)
		os.Exit(1)
	}
}

// newStdinApprover builds an Approver that reads y/n/reason from in (typically
// os.Stdin) and prints the prompt to errOut (typically os.Stderr so JSONL
// stdout stays clean for piping).
//
// Inputs:
//   - "y" / "yes"           → approve
//   - "n" / "no" / empty    → reject with default reason
//   - any other text        → reject, that text becomes the rejection reason
//     fed back to the agent (lets the operator guide the model toward a
//     lighter alternative without ending the run)
//
// Reads are serialized via a mutex so concurrent tool calls in a single
// turn would queue cleanly (Anthropic rarely emits parallel tool_use, but
// belt-and-suspenders).
func newStdinApprover(in *os.File, errOut *os.File) agent.Approver {
	br := bufio.NewReader(in)
	var mu sync.Mutex
	return func(_ context.Context, req agent.ApprovalRequest) (agent.ApprovalDecision, error) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(errOut, "\n[manual] step=%d run=%s tool=%s\n        args=%s\napprove? [y/N/<reason>] > ",
			req.Step, req.RunID, req.Tool, req.Args)
		line, err := br.ReadString('\n')
		if err != nil {
			return agent.ApprovalDecision{}, fmt.Errorf("read approval input: %w", err)
		}
		ans := strings.TrimSpace(line)
		switch strings.ToLower(ans) {
		case "y", "yes":
			return agent.ApprovalDecision{Approved: true}, nil
		case "", "n", "no":
			return agent.ApprovalDecision{Approved: false, Reason: "operator declined"}, nil
		default:
			return agent.ApprovalDecision{Approved: false, Reason: ans}, nil
		}
	}
}

func resolveStateDir(flag string, ephemeral bool) (string, error) {
	if ephemeral {
		return "", nil
	}
	if flag != "" {
		return flag, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".visor-rag", "state"), nil
}

func printBanner() {
	const (
		cyBright = "\033[38;2;0;153;204m"
		cyDark   = "\033[38;2;13;55;90m"
		cyFaint  = "\033[38;2;55;90;120m"
		rst      = "\033[0m"
		bld      = "\033[1m"
	)
	// Network graph mascot — echoes the V+node logo.
	graph := [7]string{
		`  o───o  `,
		` /|    \ `,
		`o |    o `,
		` \|   /  `,
		`  o───o  `,
		`    |    `,
		`    o    `,
	}
	// doom font — VisorRAG
	logo := [7]string{
		` _   _ _               ______  ___  _____ `,
		`| | | (_)              | ___ \/ _ \|  __ \`,
		`| | | | / __|/ _ \| '__|    /|  _  | | __ `,
		`| | | | \__ \ (_) | |  | |\ \| | | | |_\ \`,
		` \___/|_|___/\___/|_|  \_| \_\_| |_/\____/`,
		`                                           `,
		`                                           `,
	}
	fmt.Fprintln(os.Stderr)
	for i := range logo {
		fmt.Fprintf(os.Stderr, "   %s%-9s%s   %s%s%s%s\n",
			cyDark, graph[i], rst, cyBright, bld, logo[i], rst)
	}
	meta := "────  agentic recon  ·  gVisor-sandboxed  ────"
	fmt.Fprintf(os.Stderr, "\n%s%s%s\n\n", strings.Repeat(" ", 15), cyFaint+meta, rst)
}


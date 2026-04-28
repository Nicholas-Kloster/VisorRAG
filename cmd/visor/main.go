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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	)

	root := &cobra.Command{
		Use:           "visor",
		Short:         "Agentic recon over a RAG-grounded LLM with gVisor-sandboxed probes",
		SilenceUsage:  true,
		SilenceErrors: true,
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
			eng := agent.New(agent.Config{
				Model:    model,
				RAG:      ragEngine,
				Tools:    reg,
				MaxSteps: maxSteps,
				OnEvent: func(e agent.Event) {
					if quiet && e.Type != "final" && e.Type != "error" {
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

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "visor:", err)
		os.Exit(1)
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


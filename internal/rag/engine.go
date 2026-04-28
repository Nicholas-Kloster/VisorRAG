// Package rag provides a two-collection vector retrieval layer over
// VisorRAG's recon corpus, backed by chromem-go (pure Go).
//
// Collections:
//
//   - Playbooks (in-memory): embedded markdown chunks, rebuilt every start.
//     Edits to playbook .md files reach the index on the next build with no
//     migration required.
//   - Findings  (persistent): tool observations from prior agent runs.
//     Stored at <state-dir>/findings/<embedder-label>/. Namespacing by
//     embedder label means switching embedders gives a clean store rather
//     than corrupted similarity.
//
// Embedding backend selection (first match wins):
//  1. VISORRAG_EMBED=ollama  → Ollama at $OLLAMA_HOST or http://localhost:11434
//                              with model $VISORRAG_EMBED_MODEL or nomic-embed-text
//  2. VISORRAG_EMBED=openai  → OpenAI text-embedding-3-small with $OPENAI_API_KEY
//  3. OPENAI_API_KEY set     → OpenAI text-embedding-3-small (default cloud)
//  4. fallback               → Ollama nomic-embed-text at localhost:11434
package rag

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/philippgille/chromem-go"
)

// PlaybookFS is set by the root playbooks package at init time so the
// markdown files at the visible top-level /playbooks/ directory can be
// reached from this internal package (go:embed paths are package-local).
var PlaybookFS fs.FS

const (
	playbookCollName = "visor-rag-playbooks"
	findingsCollName = "visor-rag-findings"
)

type Engine struct {
	playbookDB   *chromem.DB
	playbookColl *chromem.Collection

	findingsDB   *chromem.DB         // nil when persistence disabled
	findingsColl *chromem.Collection // nil when persistence disabled
	findingsDir  string              // resolved on-disk path, "" when disabled
	embedFn      chromem.EmbeddingFunc
	embedLabel   string
}

type Hit struct {
	Source     string  // playbook filename, e.g. "cloud.md"
	Section    string  // H2 heading, e.g. "AWS IP Recon"
	Content    string  // the chunk text
	Similarity float32 // 0..1, higher is closer
}

// Finding is a tool observation persisted across runs.
type Finding struct {
	ID        string
	Target    string
	Tool      string
	RunID     string
	Step      int
	Args      string
	Output    string
	Timestamp time.Time
	Status    string // "ok" | "error"
}

// Options configure Engine construction. Embedder + Label are required.
// StateDir empty disables findings persistence (playbooks still work).
type Options struct {
	Embedder      chromem.EmbeddingFunc
	EmbedderLabel string
	StateDir      string
}

func New(ctx context.Context) (*Engine, error) {
	embedFn, label, err := pickEmbedder()
	if err != nil {
		return nil, fmt.Errorf("select embedder: %w", err)
	}
	return NewWithOptions(ctx, Options{Embedder: embedFn, EmbedderLabel: label})
}

// NewPersistent picks an embedder from environment, then opens the engine
// with findings persistence rooted at stateDir. Pass an empty stateDir to
// disable persistence (equivalent to New).
func NewPersistent(ctx context.Context, stateDir string) (*Engine, error) {
	embedFn, label, err := pickEmbedder()
	if err != nil {
		return nil, fmt.Errorf("select embedder: %w", err)
	}
	return NewWithOptions(ctx, Options{
		Embedder:      embedFn,
		EmbedderLabel: label,
		StateDir:      stateDir,
	})
}

// NewWithEmbedder builds an Engine without findings persistence.
// Kept for backwards compatibility with tests that don't need persistence.
func NewWithEmbedder(ctx context.Context, embedFn chromem.EmbeddingFunc, label string) (*Engine, error) {
	return NewWithOptions(ctx, Options{Embedder: embedFn, EmbedderLabel: label})
}

// NewWithOptions is the canonical constructor.
func NewWithOptions(ctx context.Context, opts Options) (*Engine, error) {
	if opts.Embedder == nil {
		return nil, fmt.Errorf("Options.Embedder is required")
	}
	if opts.EmbedderLabel == "" {
		opts.EmbedderLabel = "unspecified"
	}

	// Playbooks: always in-memory, always rebuilt.
	pbDB := chromem.NewDB()
	pbColl, err := pbDB.CreateCollection(playbookCollName,
		map[string]string{"embedder": opts.EmbedderLabel},
		opts.Embedder)
	if err != nil {
		return nil, fmt.Errorf("create playbook collection: %w", err)
	}
	docs, err := loadPlaybookChunks()
	if err != nil {
		return nil, fmt.Errorf("load playbooks: %w", err)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("no playbook chunks found in embedded fs")
	}
	if err := pbColl.AddDocuments(ctx, docs, 4); err != nil {
		return nil, fmt.Errorf("ingest playbooks: %w", err)
	}

	e := &Engine{
		playbookDB:   pbDB,
		playbookColl: pbColl,
		embedFn:      opts.Embedder,
		embedLabel:   opts.EmbedderLabel,
	}

	// Findings: optional persistent collection.
	if opts.StateDir != "" {
		dir := filepath.Join(opts.StateDir, "findings", sanitizeLabel(opts.EmbedderLabel))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create findings dir: %w", err)
		}
		fDB, err := chromem.NewPersistentDB(dir, true)
		if err != nil {
			return nil, fmt.Errorf("open findings db: %w", err)
		}
		fColl, err := fDB.GetOrCreateCollection(findingsCollName,
			map[string]string{"embedder": opts.EmbedderLabel},
			opts.Embedder)
		if err != nil {
			return nil, fmt.Errorf("create findings collection: %w", err)
		}
		e.findingsDB = fDB
		e.findingsColl = fColl
		e.findingsDir = dir
	}

	return e, nil
}

// HasPersistence reports whether the engine stores findings to disk.
func (e *Engine) HasPersistence() bool { return e.findingsColl != nil }

// FindingsDir returns the on-disk findings path, or "" if persistence is off.
func (e *Engine) FindingsDir() string { return e.findingsDir }

// Search returns up to k playbook chunks most relevant to query, diversified
// across source files. Strategy: take the best single match, then for each
// distinct source file in the corpus take its top match (deduped against
// what we already have). This guarantees the agent sees one chunk from each
// playbook rather than 4-from-the-same-vocabulary-winner — important when
// playbook vocabularies overlap (e.g., "recon enumeration" matches AI/ML's
// tooling-order section regardless of target type).
//
// Diversification preserves similarity ranking within each source: the
// chunk we take from cloud.md is cloud.md's BEST match for the query, not
// a random cloud.md chunk.
func (e *Engine) Search(ctx context.Context, query string, k int) ([]Hit, error) {
	if k <= 0 {
		k = 4
	}
	if e.playbookColl.Count() == 0 {
		return nil, nil
	}

	// Discover distinct source files. Cheap: query large-N once, dedupe by source.
	wide := e.playbookColl.Count()
	if wide > 32 {
		wide = 32
	}
	all, err := e.playbookColl.Query(ctx, query, wide, nil, nil)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	hits := make([]Hit, 0, k)

	// Pass 1: take overall top-1 (best similarity, regardless of source)
	if len(all) > 0 {
		r := all[0]
		hits = append(hits, Hit{
			Source:     r.Metadata["source"],
			Section:    r.Metadata["section"],
			Content:    r.Content,
			Similarity: r.Similarity,
		})
		seen[r.Metadata["source"]] = true
	}

	// Pass 2: walk the rest in similarity order, take top-1 per new source
	for _, r := range all[1:] {
		if len(hits) >= k {
			break
		}
		src := r.Metadata["source"]
		if seen[src] {
			continue
		}
		hits = append(hits, Hit{
			Source:     src,
			Section:    r.Metadata["section"],
			Content:    r.Content,
			Similarity: r.Similarity,
		})
		seen[src] = true
	}

	// Pass 3: if k > distinct sources, fill the remaining slots from the
	// query results in order, allowing source repeats. Caller asked for k
	// hits; we return up to k.
	for _, r := range all {
		if len(hits) >= k {
			break
		}
		alreadyAt := false
		for _, h := range hits {
			if h.Source == r.Metadata["source"] && h.Section == r.Metadata["section"] {
				alreadyAt = true
				break
			}
		}
		if alreadyAt {
			continue
		}
		hits = append(hits, Hit{
			Source:     r.Metadata["source"],
			Section:    r.Metadata["section"],
			Content:    r.Content,
			Similarity: r.Similarity,
		})
	}

	return hits, nil
}

// Count returns the number of indexed playbook chunks.
func (e *Engine) Count() int { return e.playbookColl.Count() }

// AddFinding persists a single tool observation. No-op when persistence
// is disabled (returns nil).
func (e *Engine) AddFinding(ctx context.Context, f Finding) error {
	if e.findingsColl == nil {
		return nil
	}
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now().UTC()
	}
	if f.ID == "" {
		f.ID = fmt.Sprintf("%s::%s::%s::%d", f.Target, f.RunID, f.Tool, f.Step)
	}
	if f.Status == "" {
		if strings.HasPrefix(strings.TrimSpace(f.Output), "ERROR:") {
			f.Status = "error"
		} else {
			f.Status = "ok"
		}
	}
	doc := chromem.Document{
		ID:      f.ID,
		Content: f.Output,
		Metadata: map[string]string{
			"target":    f.Target,
			"tool":      f.Tool,
			"run_id":    f.RunID,
			"step":      fmt.Sprintf("%d", f.Step),
			"args":      f.Args,
			"timestamp": f.Timestamp.UTC().Format(time.RFC3339Nano),
			"status":    f.Status,
		},
	}
	return e.findingsColl.AddDocument(ctx, doc)
}

// FindingsForTarget returns up to k prior findings for the given target,
// most recent first. Returns nil when persistence is disabled.
//
// Implementation note: chromem-go's Query is similarity-based. We use the
// target string as the query and filter by metadata.target, then sort the
// returned slice by timestamp descending. For small per-target findings
// pools this is fine; if pools grow large we'd switch to a full scan.
func (e *Engine) FindingsForTarget(ctx context.Context, target string, k int) ([]Finding, error) {
	if e.findingsColl == nil {
		return nil, nil
	}
	if e.findingsColl.Count() == 0 {
		return nil, nil
	}
	if k <= 0 {
		k = 6
	}
	queryK := k * 2 // overshoot since we re-sort by time
	if queryK > e.findingsColl.Count() {
		queryK = e.findingsColl.Count()
	}
	q := fmt.Sprintf("recon findings for %s recent observations", target)
	res, err := e.findingsColl.Query(ctx, q, queryK,
		map[string]string{"target": target}, nil)
	if err != nil {
		return nil, err
	}
	out := make([]Finding, 0, len(res))
	for _, r := range res {
		f := Finding{
			ID:     r.ID,
			Target: r.Metadata["target"],
			Tool:   r.Metadata["tool"],
			RunID:  r.Metadata["run_id"],
			Args:   r.Metadata["args"],
			Status: r.Metadata["status"],
			Output: r.Content,
		}
		if t, err := time.Parse(time.RFC3339Nano, r.Metadata["timestamp"]); err == nil {
			f.Timestamp = t
		}
		fmt.Sscanf(r.Metadata["step"], "%d", &f.Step)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Timestamp.After(out[j].Timestamp)
	})
	if len(out) > k {
		out = out[:k]
	}
	return out, nil
}

// FindingsCount returns the total findings persisted (0 if disabled).
func (e *Engine) FindingsCount() int {
	if e.findingsColl == nil {
		return 0
	}
	return e.findingsColl.Count()
}

func loadPlaybookChunks() ([]chromem.Document, error) {
	if PlaybookFS == nil {
		return nil, fmt.Errorf("rag.PlaybookFS not initialized — import _ \"github.com/Nicholas-Kloster/visor-rag/playbooks\" from main")
	}
	var docs []chromem.Document
	err := fs.WalkDir(PlaybookFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}
		data, err := fs.ReadFile(PlaybookFS, path)
		if err != nil {
			return err
		}
		base := filepath.Base(path)
		for _, c := range chunkMarkdownByH2(string(data)) {
			id := fmt.Sprintf("%s#%s", base, c.section)
			docs = append(docs, chromem.Document{
				ID:      id,
				Content: c.body,
				Metadata: map[string]string{
					"source":  base,
					"section": c.section,
				},
			})
		}
		return nil
	})
	return docs, err
}

type chunk struct {
	section string
	body    string
}

// chunkMarkdownByH2 splits a markdown document into chunks at every "## "
// heading. Content above the first H2 (typically the H1 + intro) is emitted
// as a "preamble" chunk.
func chunkMarkdownByH2(md string) []chunk {
	lines := strings.Split(md, "\n")
	var (
		out     []chunk
		curSec  = "preamble"
		curBody strings.Builder
		flush   = func() {
			body := strings.TrimSpace(curBody.String())
			if body != "" {
				out = append(out, chunk{section: curSec, body: body})
			}
			curBody.Reset()
		}
	)
	for _, ln := range lines {
		if strings.HasPrefix(ln, "## ") {
			flush()
			curSec = strings.TrimSpace(strings.TrimPrefix(ln, "## "))
			continue
		}
		curBody.WriteString(ln)
		curBody.WriteByte('\n')
	}
	flush()
	return out
}

// sanitizeLabel makes an embedder label safe to use as a directory name.
func sanitizeLabel(s string) string {
	r := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		" ", "_",
	)
	return r.Replace(s)
}

// ---------- embedder selection ----------

func pickEmbedder() (chromem.EmbeddingFunc, string, error) {
	switch strings.ToLower(os.Getenv("VISORRAG_EMBED")) {
	case "ollama":
		return ollamaEmbedder()
	case "openai":
		return openaiEmbedder()
	}
	if os.Getenv("OPENAI_API_KEY") != "" {
		return openaiEmbedder()
	}
	return ollamaEmbedder()
}

func ollamaEmbedder() (chromem.EmbeddingFunc, string, error) {
	host := os.Getenv("OLLAMA_HOST")
	if host == "" {
		host = "http://localhost:11434"
	}
	if !strings.HasPrefix(host, "http") {
		host = "http://" + host
	}
	model := os.Getenv("VISORRAG_EMBED_MODEL")
	if model == "" {
		model = "nomic-embed-text"
	}
	baseAPI := strings.TrimSuffix(host, "/") + "/api"
	return chromem.NewEmbeddingFuncOllama(model, baseAPI), fmt.Sprintf("ollama:%s", model), nil
}

func openaiEmbedder() (chromem.EmbeddingFunc, string, error) {
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		return nil, "", fmt.Errorf("OPENAI_API_KEY not set")
	}
	model := os.Getenv("VISORRAG_EMBED_MODEL")
	em := chromem.EmbeddingModelOpenAI3Small
	if model != "" {
		em = chromem.EmbeddingModelOpenAI(model)
	}
	return chromem.NewEmbeddingFuncOpenAI(key, em), fmt.Sprintf("openai:%s", em), nil
}

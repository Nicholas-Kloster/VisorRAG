// Package rag provides a zero-dependency vector retrieval layer over
// VisorRAG's recon playbooks. Backed by chromem-go (pure Go), with playbook
// markdown embedded into the binary via go:embed.
//
// Embedding backend selection (first match wins):
//  1. VISORRAG_EMBED=ollama  → Ollama at $OLLAMA_HOST or http://localhost:11434
//                              with model $VISORRAG_EMBED_MODEL or nomic-embed-text
//  2. VISORRAG_EMBED=openai  → OpenAI text-embedding-3-small with $OPENAI_API_KEY
//  3. OPENAI_API_KEY set     → OpenAI text-embedding-3-small (default cloud)
//  4. fallback               → Ollama nomic-embed-text at localhost:11434
//
// The whole DB is in-memory; rebuilt on every process start. Playbooks are
// chunked by H2 (##) section so each result lands a topical block, not a
// whole document.
package rag

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/philippgille/chromem-go"
)

// PlaybookFS is set by the root playbooks package at init time so the
// markdown files at the visible top-level /playbooks/ directory can be
// reached from this internal package (go:embed paths are package-local).
var PlaybookFS fs.FS

const collectionName = "visor-rag-playbooks"

type Engine struct {
	db   *chromem.DB
	coll *chromem.Collection
}

type Hit struct {
	Source     string  // playbook filename, e.g. "cloud.md"
	Section    string  // H2 heading, e.g. "AWS IP Recon"
	Content    string  // the chunk text
	Similarity float32 // 0..1, higher is closer
}

func New(ctx context.Context) (*Engine, error) {
	embedFn, label, err := pickEmbedder()
	if err != nil {
		return nil, fmt.Errorf("select embedder: %w", err)
	}
	return NewWithEmbedder(ctx, embedFn, label)
}

// NewWithEmbedder builds an Engine with a caller-supplied embedding func.
// Used by tests to swap in a deterministic in-process embedder, and by
// callers that want to wire a custom embedding backend without going
// through environment variables.
func NewWithEmbedder(ctx context.Context, embedFn chromem.EmbeddingFunc, label string) (*Engine, error) {
	db := chromem.NewDB()
	coll, err := db.CreateCollection(collectionName, map[string]string{"embedder": label}, embedFn)
	if err != nil {
		return nil, fmt.Errorf("create collection: %w", err)
	}
	docs, err := loadPlaybookChunks()
	if err != nil {
		return nil, fmt.Errorf("load playbooks: %w", err)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("no playbook chunks found in embedded fs")
	}
	if err := coll.AddDocuments(ctx, docs, 4); err != nil {
		return nil, fmt.Errorf("ingest playbooks: %w", err)
	}
	return &Engine{db: db, coll: coll}, nil
}

// Search returns up to k playbook chunks most relevant to query.
func (e *Engine) Search(ctx context.Context, query string, k int) ([]Hit, error) {
	if k <= 0 {
		k = 4
	}
	if e.coll.Count() == 0 {
		return nil, nil
	}
	// chromem-go errors when nResults > collection size.
	if k > e.coll.Count() {
		k = e.coll.Count()
	}
	res, err := e.coll.Query(ctx, query, k, nil, nil)
	if err != nil {
		return nil, err
	}
	hits := make([]Hit, 0, len(res))
	for _, r := range res {
		hits = append(hits, Hit{
			Source:     r.Metadata["source"],
			Section:    r.Metadata["section"],
			Content:    r.Content,
			Similarity: r.Similarity,
		})
	}
	return hits, nil
}

// Count returns the number of indexed chunks (for debug / diagnostics).
func (e *Engine) Count() int { return e.coll.Count() }

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
		out      []chunk
		curSec   = "preamble"
		curBody  strings.Builder
		flush    = func() {
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
	// chromem-go's Ollama embedder appends /api at call time; pass base URL.
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

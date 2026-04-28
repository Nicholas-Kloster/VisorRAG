// Package playbooks embeds the markdown recon playbooks into the binary
// and registers them with the RAG engine. Side-effect import only:
//
//	import _ "github.com/Nicholas-Kloster/visor-rag/playbooks"
//
// Drop a new playbook in this directory and it gets picked up on the next
// build automatically.
package playbooks

import (
	"embed"
	"io/fs"

	"github.com/Nicholas-Kloster/visor-rag/internal/rag"
)

// Embed top-level playbooks (cloud/web/api/ai-ml.md) plus the entire
// ai-osint/ subdirectory (curated catalogue from
// github.com/Nicholas-Kloster/AI-LLM-Infrastructure-OSINT — Shodan queries
// and service fingerprints for AI/ML infra). The RAG WalkDir picks up
// nested .md files automatically; the diversified Search now ensures
// per-source coverage so AI-LLM-OSINT chunks don't crowd out general
// playbooks for non-AI targets.
//
//go:embed *.md ai-osint
var fsRoot embed.FS

func init() {
	sub, err := fs.Sub(fsRoot, ".")
	if err != nil {
		panic(err)
	}
	rag.PlaybookFS = sub
}

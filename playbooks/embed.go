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

//go:embed *.md
var fsRoot embed.FS

func init() {
	sub, err := fs.Sub(fsRoot, ".")
	if err != nil {
		panic(err)
	}
	rag.PlaybookFS = sub
}

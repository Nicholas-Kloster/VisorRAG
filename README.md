<p align="center">
  <img src="assets/logo.png" width="220" alt="VisorRAG">
</p>

<h1 align="center">VisorRAG</h1>
<p align="center"><em>Agentic recon driven by a RAG-grounded LLM · every probe sandboxed in gVisor</em></p>

---

## What it is

VisorRAG is a single binary that wraps a ReAct-loop LLM agent over a two-collection vector store. You hand it a target; it decides what to probe, runs each tool in an isolated gVisor sandbox, embeds the observations into a persistent findings store, and iterates until it has a picture of the attack surface.

The default tool lineup is NuClide-authored — VisorGraph for provenance-graph recon and aimap for AI/ML service deep enumeration — chosen specifically because commodity scanners (nuclei, httpx, naabu) hit auth walls and template directory requirements that make unattended runs unreliable.

---

## Architecture

```
visor CLI
  └── agent (ReAct loop, Anthropic / OpenAI)
        ├── rag (chromem-go)
        │     ├── playbooks/  — embedded markdown (ai-ml, api, cloud, web)
        │     └── findings/   — persistent observations, namespaced by embedder
        ├── tools
        │     ├── visorgraph  — seed-polymorphic recon graph
        │     └── aimap       — 36-service AI/ML fingerprinter
        └── sandbox (gVisor runsc)
              └── every tool call runs in an OCI bundle
```

---

## Requirements

- Go 1.22+
- [gVisor](https://gvisor.dev/docs/user_guide/install/) (`runsc` in `$PATH`)
- `ANTHROPIC_API_KEY` **or** `OPENAI_API_KEY`
- `visorgraph` and/or `aimap` binaries in `$PATH`

Embedding backend (first match wins):

| Priority | Condition | Backend |
|---|---|---|
| 1 | `VISORRAG_EMBED=ollama` | Ollama at `$OLLAMA_HOST` |
| 2 | `VISORRAG_EMBED=openai` | OpenAI `text-embedding-3-small` |
| 3 | `OPENAI_API_KEY` set | OpenAI `text-embedding-3-small` |
| 4 | fallback | Ollama `nomic-embed-text` at localhost:11434 |

---

## Install

```bash
git clone https://github.com/Nicholas-Kloster/VisorRAG
cd VisorRAG
go build -o visor ./cmd/visor
```

---

## Usage

```bash
# Basic run — agent decides steps automatically
visor --target 192.0.2.1

# Cap the ReAct loop
visor --target example.com --max-steps 8

# Override the model
visor --target 10.0.0.0/24 --model claude-opus-4-7

# Ephemeral run — no findings written to disk
visor --target 192.0.2.1 --ephemeral

# Manual step confirmation
visor --target 192.0.2.1 --manual

# Keep state between sessions
visor --target 192.0.2.1 --state-dir ~/.visor/sessions/target-1
```

---

## Playbooks

Markdown documents embedded at build time and loaded into the RAG index on startup. The agent retrieves relevant chunks before each ReAct step.

| Playbook | Coverage |
|---|---|
| `ai-ml.md` | AI/ML infrastructure discovery, vector DBs, inference endpoints |
| `api.md` | API reconnaissance, auth bypass, key enumeration |
| `cloud.md` | Cloud asset enumeration, bucket discovery, metadata endpoints |
| `web.md` | Web recon, header analysis, JS secrets, redirect chains |

---

## Related

- **[VisorGraph](https://github.com/Nicholas-Kloster/VisorGraph)** — seed-polymorphic recon graph engine (used as default tool)
- **[aimap](https://github.com/Nicholas-Kloster/aimap)** — AI/ML infrastructure deep enumerator (used as default tool)
- **[JAXEN](https://github.com/Nicholas-Kloster/JAXEN)** — Shodan-powered recon platform, feeds targets into VisorRAG
- **[BARE](https://github.com/Nicholas-Kloster/BARE)** — semantic exploit matching against Metasploit corpus

---

## License

MIT

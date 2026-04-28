# AI/ML Infrastructure Recon Playbook

## When to use
Target hosts LLM APIs, vector databases, model servers, MLflow, agent
platforms, or any AI/ML-adjacent service. AI/ML infra has specific
exposure patterns the commodity scanners miss — surface PII, unauth RCE,
exposed credentials, claimable admin states.

## Default reach: aimap
The aimap tool (github.com/Nicholas-Kloster/aimap) fingerprints 36 AI/ML
services and runs 26 dedicated deep enumerators. Reach for aimap before
nuclei when AI/ML signals are present.

## Service signals to look for
- Ollama: port 11434, /api/tags, /api/generate, /api/show
- vLLM / Text Generation WebUI: port 5000, 7860, 8080
- LM Studio: port 1234, OpenAI-compatible /v1/models
- Open WebUI / Lobe Chat / Anything LLM: ports 3000, 8080, model lists
  exposed unauth often
- LiteLLM proxy: /model/info, /key/info — often expose upstream API keys
- LocalAI: port 8080, /v1/models
- Triton Inference Server: ports 8000, 8001, 8002, /v2/models
- TorchServe: 8080 (inference), 8081 (management), 8082 (metrics) —
  management API on 8081 enables model upload (RCE primitive)
- BentoML / MLflow: port 5000, /api/2.0/mlflow/* — model registry,
  experiment tracking, often unauth
- Ray Dashboard: port 8265 — job submission API enables RCE
- Kubeflow Pipelines: port 8080
- Weaviate: port 8080, /v1/schema
- Qdrant: port 6333, /collections
- Milvus: port 19530, gRPC + HTTP 9091
- ChromaDB: port 8000, /api/v1/collections
- Pinecone (cloud-only typically), but self-hosted alternatives common

## High-impact misconfigurations
- LiteLLM proxy with master key in URL or default 'sk-1234'
- Ollama exposed unauth — model exfil + CPU/GPU resource theft
  (LLMjacking)
- vLLM /v1/chat/completions unauth — prompt injection, content policy
  bypass, quota drain
- MLflow tracking server unauth — pickle deserialization on model load
- Ray Dashboard unauth — POST /api/jobs/ with arbitrary entrypoint = RCE
- TorchServe management API on 8081 — model upload + model load = RCE
- ChromaDB unauth — vector DB contents often contain RAG document
  chunks with PII, internal docs, source code
- Hugging Face Spaces / Gradio dev mode — eval() RCE on model upload

## Probe patterns
- For LLM APIs: send /v1/models or /api/tags first to enumerate models,
  then check whether /v1/chat/completions accepts requests without auth
- For vector DBs: list collections, sample one document — content
  reveals what RAG corpus they're using
- For pipeline orchestrators: list jobs/experiments — leaks pipeline
  names, model names, sometimes data paths

## Tooling order
1. aimap-profile — classify the target (research / commercial / personal)
   before any active probe
2. aimap — fingerprint + deep enumeration
3. httpx — supplementary surface coverage
4. nuclei with custom AI-specific templates

# API Recon Playbook

## When to use
Target exposes REST, GraphQL, or RPC APIs. Goal: enumerate the surface,
identify auth model, find broken object-level authorization (BOLA), find
unauth endpoints, surface schema introspection.

## REST surface enumeration
- /openapi.json, /swagger.json, /api-docs, /v2/api-docs — schema dumps
  reveal every endpoint including unlinked admin ones
- /graphql, /graphiql, /altair — GraphQL endpoint signatures
- /api, /api/v1, /api/v2, /rest — common base paths to fuzz
- HEAD vs GET vs OPTIONS — tampering can bypass auth middleware that
  only checks GET

## GraphQL specifics
- Introspection query (__schema) often left enabled in prod
- Field suggestions ("Did you mean ...?") leak schema even with
  introspection disabled
- Query depth and complexity often unbounded — denial of wallet
- Aliasing enables auth bypass / BOLA enumeration in single request
- Batching attacks: multiple operations in one request often bypass
  rate-limiting

## Auth probing
- Bearer token reflection: send your own token, see if endpoint
  validates user_id from token vs URL
- JWT alg=none, alg=HS256 with public key as secret, weak secret brute
- API key in URL parameter (?api_key=) — leak risk via referrer logs
- Cookie + Bearer hybrid — confused deputy bypass when both are sent

## High-value endpoints
- /api/users, /api/users/me — IDOR test target
- /api/admin, /api/internal — auth bypass test target
- /api/upload, /api/files — file upload + path traversal
- /api/webhooks, /api/callbacks — SSRF + open redirect
- /api/export, /api/download — auth + IDOR + path traversal

## Tooling order
- httpx for HTTP enumeration
- ffuf / gobuster with API-specific wordlists (api-endpoints.txt)
- nuclei with exposures/apis/, technologies/, vulnerabilities/ templates
- For GraphQL: clairvoyance, graphql-cop, inql

## Telltale headers
- X-RateLimit-Limit / X-RateLimit-Remaining — confirms API gateway
- Apigee, Kong, Tyk, AWS API Gateway distinct error response shapes
- Location header on 30x for resource creation reveals ID format

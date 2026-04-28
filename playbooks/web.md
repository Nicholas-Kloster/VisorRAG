# Web Application Recon Playbook

## When to use
Target exposes HTTP(S) on standard or non-standard ports. Goal: identify
framework, surface admin/management interfaces, find exposed config or
debug endpoints.

## First-pass enumeration
1. httpx against target with -title -tech-detect -status-code -tls-probe
   -follow-redirects. Capture the Server header, X-Powered-By, framework
   detection, TLS cert SANs.
2. Probe direct-IP TLS without SNI — surfaces default certs that often name
   the actual customer/tenant on shared infrastructure (CDN, ALB).
3. Pull /robots.txt, /.well-known/security.txt, /sitemap.xml, /humans.txt.
   Often reveals admin panels, dev URLs, contact emails for disclosure.

## Common exposure paths
- /actuator/* (Spring Boot) — health, env, beans, mappings often unauth
- /metrics, /debug/vars, /debug/pprof (Go) — info disclosure
- /api/v1, /swagger.json, /openapi.json — API surface enumeration
- /.env, /.git/config, /.DS_Store — config / source leakage
- /admin, /panel, /console, /manager — auth-required panels
- /server-status, /server-info — Apache mod_status leakage
- /wp-json/wp/v2/users — WordPress user enumeration

## Tech-specific signals
- Spring Boot: actuator endpoints, X-Application-Context header
- Django: csrftoken cookie, CSRF_TOKEN in HTML
- Rails: _session cookie format, X-Runtime header
- Express/Node: X-Powered-By: Express, etag format
- Drupal: X-Drupal-Cache header, /sites/default/files/ paths
- Laravel: laravel_session cookie, X-Powered-By: PHP

## Tooling order
- visorgraph for surface enumeration — CT logs reveal subdomains, HTTP probes
  surface titles + tech stack, TLS analysis pulls cert SANs and OV/EV
  customer attribution. One call returns a typed provenance graph.
- Targeted content discovery and vuln scanning are out of VisorRAG's current
  toolset — flag promising surface for manual follow-up by the operator.

## Auth bypass / quick wins to check
- Default credentials on admin panels (admin/admin, admin/password)
- JWT alg=none token forgery
- Path traversal on file-serving endpoints
- IDOR on numeric/UUID resource identifiers
- HTTP method tampering (GET → POST, OPTIONS verb tampering)

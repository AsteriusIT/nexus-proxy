# Nexus Proxy

A transparent proxy for **package registries**, designed to work alongside **Sonatype Nexus Repository Manager**. When a security scanner is active, npm downloads are scanned on the fly and blocked if vulnerabilities exceed the severity threshold.

## Supported package formats

| Format       | Status    |
|-------------|-----------|
| **npm**     | Supported (with optional security scanning) |
| **PyPI**    | Supported |
| **Maven**   | Supported |
| **NuGet**   | Supported |
| **RubyGems**| Supported |

## How it works

1. **Metadata** (e.g. npm package manifest) is proxied from the upstream registry and returned to the client. Download URLs in the response are rewritten to route through the proxy.
2. **Downloads** are forwarded transparently to the upstream registry.
3. When a **security scanner** is active (Trivy or Checkmarx), npm tarball downloads are scanned before being served — packages with blocking vulnerabilities are rejected with `403`.

## Quick start

```bash
docker-compose up -d
```

This starts Nexus and the proxy. The proxy is available internally on port 80; Nexus is exposed on `http://localhost:8081`.

For local development:

```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

OpenAPI docs: `http://localhost:8000/docs`

## Authentication

Set `PROXY_BEARER_TOKEN` to require a Bearer token on all requests:

```bash
export PROXY_BEARER_TOKEN=your-secret-token
```

Alternatively, use `PROXY_BEARER_TOKEN_FILE` to read the token from a file. If neither is set, the API is open.

## Security scanning

Activate a scanner via environment variable or at runtime:

```bash
# Via env var
export SECURITY_SCANNER=osv

# Or at runtime
curl -X PUT http://localhost:8000/admin/scanner \
  -H "Content-Type: application/json" \
  -d '{"name": "osv"}'
```

Available scanners:
- **osv** — queries [OSV.dev](https://osv.dev) REST API (free, no setup needed)
- **checkmarx** — Checkmarx One SCA (requires API credentials)

When active, npm tarball downloads are scanned on the fly. Scan results are cached in memory. Scanner errors are fail-open (downloads are allowed if the scanner is unavailable).

## Documentation

- [Deployment Guide](docs/deployment.md) — Docker Compose, standalone Docker, Python, Nexus configuration, scanner setup
- [Usage Guide](docs/usage.md) — per-registry examples, security scanning workflow, API reference

## Project layout

```
app/
  main.py              # FastAPI app, mounts routers
  config.py            # Proxy config (Bearer token)
  auth.py              # Bearer token dependency
  http_client.py       # Async HTTP client factory
  scanner.py           # Scanner abstraction + registry
  scanners/
    checkmarx.py       # Checkmarx One SCA scanner
    osv.py             # OSV.dev REST API scanner
  routers/
    admin.py           # Scanner management endpoints
    npm.py             # npm registry proxy + scanning
    pypi.py            # PyPI registry proxy
    maven.py           # Maven Central proxy
    nuget.py           # NuGet v3 proxy
    rubygems.py        # RubyGems proxy
docs/
  deployment.md        # Deployment guide
  usage.md             # Usage guide
tests/
  npm/                 # Test config for npm
```

## License

See repository for license information.

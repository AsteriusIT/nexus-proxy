# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Nexus-proxy is a FastAPI-based transparent proxy for package registries. All requests are forwarded to upstream registries with download URLs rewritten to route through the proxy. When a security scanner is active, package downloads across all registries (npm, PyPI, Maven, NuGet, RubyGems) are scanned on the fly and blocked if vulnerabilities exceed the severity threshold. Scanner errors are fail-open (development is not blocked by infrastructure issues).

### Supported registries

| Registry   | Prefix        | Upstream                          |
|------------|---------------|-----------------------------------|
| npm        | `/npm`        | registry.npmjs.org                |
| PyPI       | `/pypi`       | pypi.org / files.pythonhosted.org |
| Maven      | `/maven`      | repo1.maven.org/maven2            |
| NuGet      | `/nuget`      | api.nuget.org                     |
| RubyGems   | `/rubygems`   | rubygems.org                      |

## Commands

### Run locally
```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Run with Docker Compose (includes Nexus)
```bash
docker-compose up -d
```

### Dockerfile linting (used in CI)
```bash
hadolint Dockerfile
```

### Testing
There are no pytest/unittest tests. Testing is manual:
```bash
cd tests/npm && npm install

# Clean up Nexus repository
./tests/npm/clean.sh
```

## Architecture

**Entry point:** `app/main.py` — creates the FastAPI app with Swagger/OpenAPI docs, mounts all registry routers, manages HTTP client lifecycle via lifespan, exposes `/health`.

**Shared modules:**
- `app/http_client.py` — HTTP client factory. One `httpx.AsyncClient` per upstream registry, lazy-init, closed on shutdown via lifespan.

**Auth:** `app/auth.py` — Bearer token via `Depends()`. If `PROXY_BEARER_TOKEN` (or `PROXY_BEARER_TOKEN_FILE`) is set, all routes require it. If unset, the API is open.

**Config:** `app/config.py` — reads bearer token from env var or file (env takes precedence).

**Registry routers** (all under `app/routers/`):

- `admin.py` — admin endpoints for managing security scanners at runtime (`GET/PUT /admin/scanner`).

- `npm.py` — npm registry. Metadata endpoints fetch from upstream and rewrite tarball URLs. Tarball downloads are streamed in 64KB chunks. When a scanner is active, downloads are scanned on the fly (results cached by package@version). Supports scoped (`@scope/name`) and unscoped packages.

- `pypi.py` — PyPI registry. Supports Simple API (PEP 503), JSON metadata API, and file downloads from `files.pythonhosted.org`. Package names are PEP 503-normalized. When a scanner is active, file downloads are scanned on the fly (name/version extracted from filename).

- `maven.py` — Maven Central. Path-based layout (`groupId/artifactId/version/file`). Metadata and artifact downloads separated into `/metadata/` and `/artifact/` prefixed paths. When a scanner is active, artifact downloads are scanned on the fly (coordinates extracted from path).

- `nuget.py` — NuGet v3 API. Proxies service index, search, registration, and flat container endpoints. URLs in responses are rewritten. When a scanner is active, `.nupkg` downloads are scanned on the fly.

- `rubygems.py` — RubyGems.org. Supports JSON API, compact index, dependency resolution, and `.gem` file downloads. When a scanner is active, gem downloads are scanned on the fly (name/version extracted from filename).

**Security scanning** (under `app/`):

- `scanner.py` — abstract scanner interface (`SecurityScanner`), `ScanResult`/`ScanStatus` models, and a provider registry. Admins can hot-swap the active scanner via `PUT /admin/scanner` or set the `SECURITY_SCANNER` env var.
- `scanners/osv.py` — OSV.dev implementation. Queries the OSV.dev REST API (`POST /v1/query`) with package name + version. No binary, no temp files — just an HTTP call. Free, unauthenticated, aggregates from 24 vulnerability sources (GitHub Advisory DB, NVD, etc.). Fail-open on API errors.
- `scanners/checkmarx.py` — Checkmarx MPAPI implementation. Queries the Checkmarx Malicious Package Identification API (`POST /v1/packages`) with package name, type, and version. No OAuth, no project management — just a single HTTP call. Returns supply-chain risks (malicious packages, data leakage, star-jacking, etc.). Fail-open on API errors.

### Environment variables

| Variable                  | Default                              | Description                        |
|---------------------------|--------------------------------------|------------------------------------|
| `PROXY_BEARER_TOKEN`      | *(none)*                             | Bearer token for API auth          |
| `PROXY_BEARER_TOKEN_FILE` | *(none)*                             | File path to read bearer token     |
| `NPM_UPSTREAM_REGISTRY`   | `https://registry.npmjs.org`         | npm upstream URL                   |
| `PYPI_UPSTREAM_SIMPLE`    | `https://pypi.org/simple`            | PyPI Simple API URL                |
| `PYPI_UPSTREAM_FILES`     | `https://files.pythonhosted.org`     | PyPI file hosting URL              |
| `MAVEN_UPSTREAM_URL`      | `https://repo1.maven.org/maven2`    | Maven Central URL                  |
| `NUGET_UPSTREAM_URL`      | `https://api.nuget.org`             | NuGet v3 API URL                   |
| `RUBYGEMS_UPSTREAM_URL`   | `https://rubygems.org`              | RubyGems URL                       |
| `SECURITY_SCANNER`        | *(none)*                             | Active scanner name (e.g. `osv`, `checkmarx`) |
| `OSV_API_URL`             | `https://api.osv.dev`               | OSV.dev API base URL               |
| `OSV_TIMEOUT`             | `30`                                 | HTTP request timeout in seconds    |
| `OSV_SEVERITY_THRESHOLD`  | `CRITICAL,HIGH`                      | Severities that block download     |
| `CHECKMARX_MPAPI_URL`     | `https://api.dusti.co/v1/packages`  | Checkmarx MPAPI endpoint URL       |
| `CHECKMARX_MPAPI_TOKEN`   | *(required if scanner active)*       | MPAPI token from Checkmarx         |
| `CHECKMARX_MPAPI_TIMEOUT` | `30`                                 | HTTP request timeout in seconds    |
| `CHECKMARX_SEVERITY_THRESHOLD` | `CRITICAL,HIGH`               | Severities that block download     |

## CI Pipeline

`.github/workflows/containe-ci.yml` runs on all pushes/PRs: hadolint → docker build → dockle (CIS benchmark) → dive (image efficiency, config in `.dive-ci.yml`) → trivy (vulnerability scan).

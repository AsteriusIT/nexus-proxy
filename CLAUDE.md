# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Nexus-proxy is a FastAPI-based transparent proxy for package registries that enforces package whitelisting. Only whitelisted packages can be downloaded; metadata is proxied transparently with download URLs rewritten to route through the proxy. After a successful download, the package is removed from the whitelist (Nexus caches it, so no repeated proxy downloads needed). State is in-memory and lost on restart.

### Supported registries

| Registry   | Prefix        | Upstream                          | Whitelist key              |
|------------|---------------|-----------------------------------|----------------------------|
| npm        | `/npm`        | registry.npmjs.org                | scope + package name       |
| PyPI       | `/pypi`       | pypi.org / files.pythonhosted.org | normalized package name    |
| Maven      | `/maven`      | repo1.maven.org/maven2            | groupId + artifactId       |
| NuGet      | `/nuget`      | api.nuget.org                     | lowercase package ID       |
| RubyGems   | `/rubygems`   | rubygems.org                      | gem name                   |

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

### No automated test suite
There are no pytest/unittest tests. Testing is manual via shell scripts in `tests/npm/`:
```bash
# Whitelist all packages from a lock file, then npm install
./tests/npm/whitelist-all.bash tests/npm/package-lock.json
cd tests/npm && npm install

# Clean up Nexus repository
./tests/npm/clean.sh
```

## Architecture

**Entry point:** `app/main.py` — creates the FastAPI app with Swagger/OpenAPI docs, mounts all registry routers, manages HTTP client lifecycle via lifespan, exposes `/health`.

**Shared modules:**
- `app/whitelist.py` — registry-aware in-memory whitelist. Keyed by `(registry, namespace, package)`.
- `app/http_client.py` — HTTP client factory. One `httpx.AsyncClient` per upstream registry, lazy-init, closed on shutdown via lifespan.

**Auth:** `app/auth.py` — Bearer token via `Depends()`. If `PROXY_BEARER_TOKEN` (or `PROXY_BEARER_TOKEN_FILE`) is set, all routes require it. If unset, the API is open.

**Config:** `app/config.py` — reads bearer token from env var or file (env takes precedence).

**Registry routers** (all under `app/routers/`):

- `npm.py` — npm registry. Metadata endpoints fetch from upstream and rewrite tarball URLs. Tarball downloads are streamed in 64KB chunks, gated by whitelist. Supports scoped (`@scope/name`) and unscoped packages.

- `pypi.py` — PyPI registry. Supports Simple API (PEP 503), JSON metadata API, and file downloads from `files.pythonhosted.org`. Package names are PEP 503-normalized.

- `maven.py` — Maven Central. Path-based layout (`groupId/artifactId/version/file`). Metadata and artifact downloads separated into `/metadata/` and `/artifact/` prefixed paths. Whitelist keyed on `groupId:artifactId`.

- `nuget.py` — NuGet v3 API. Proxies service index, search, registration, and flat container endpoints. URLs in responses are rewritten. Downloads gated on lowercase package ID.

- `rubygems.py` — RubyGems.org. Supports JSON API, compact index, dependency resolution, and `.gem` file downloads. Gem names extracted from filenames.

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

## CI Pipeline

`.github/workflows/containe-ci.yml` runs on all pushes/PRs: hadolint → docker build → dockle (CIS benchmark) → dive (image efficiency, config in `.dive-ci.yml`) → trivy (vulnerability scan).

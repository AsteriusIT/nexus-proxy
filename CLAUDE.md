# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Nexus-proxy is a FastAPI-based transparent proxy for package registries. All requests are forwarded to upstream registries with download URLs rewritten to route through the proxy. When a security scanner is active, npm tarball downloads are scanned on the fly and blocked if vulnerabilities exceed the severity threshold. Scanner errors are fail-open (development is not blocked by infrastructure issues).

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

### Run with Docker Compose (includes Nexus + Trivy)
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

- `pypi.py` — PyPI registry. Supports Simple API (PEP 503), JSON metadata API, and file downloads from `files.pythonhosted.org`. Package names are PEP 503-normalized. Downloads forwarded transparently.

- `maven.py` — Maven Central. Path-based layout (`groupId/artifactId/version/file`). Metadata and artifact downloads separated into `/metadata/` and `/artifact/` prefixed paths. Downloads forwarded transparently.

- `nuget.py` — NuGet v3 API. Proxies service index, search, registration, and flat container endpoints. URLs in responses are rewritten. Downloads forwarded transparently.

- `rubygems.py` — RubyGems.org. Supports JSON API, compact index, dependency resolution, and `.gem` file downloads.

**Security scanning** (under `app/`):

- `scanner.py` — abstract scanner interface (`SecurityScanner`), `ScanResult`/`ScanStatus` models, and a provider registry. Admins can hot-swap the active scanner via `PUT /admin/scanner` or set the `SECURITY_SCANNER` env var.
- `scanners/checkmarx.py` — Checkmarx One SCA implementation. Creates a minimal `package.json` for the requested package, ZIPs it, uploads via presigned URL, triggers an SCA-only scan, polls for completion, and returns vulnerabilities. Fail-open on scanner errors.
- `scanners/trivy.py` — Trivy implementation. Runs `trivy fs` as a subprocess against a temp directory containing a `package.json`. Supports optional client/server mode via `TRIVY_SERVER_URL`. Fail-open on scanner errors.

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
| `SECURITY_SCANNER`        | *(none)*                             | Active scanner name (e.g. `checkmarx`, `trivy`) |
| `CHECKMARX_BASE_URL`      | `https://eu-2.ast.checkmarx.net`    | Checkmarx One API base URL         |
| `CHECKMARX_IAM_URL`       | `https://eu-2.iam.checkmarx.net`    | Checkmarx IAM base URL             |
| `CHECKMARX_TENANT`        | *(required if scanner active)*       | Tenant / realm name                |
| `CHECKMARX_CLIENT_ID`     | *(required if scanner active)*       | OAuth2 client ID                   |
| `CHECKMARX_CLIENT_SECRET` | *(required if scanner active)*       | OAuth2 client secret               |
| `CHECKMARX_PROJECT_NAME`  | `nexus-proxy-sca`                    | Checkmarx project name             |
| `CHECKMARX_SCAN_TIMEOUT`  | `300`                                | Max seconds to wait for scan       |
| `CHECKMARX_SEVERITY_THRESHOLD` | `CRITICAL,HIGH`               | Severities that block download     |
| `TRIVY_BINARY`            | `trivy`                              | Path to the Trivy binary           |
| `TRIVY_SERVER_URL`        | *(none)*                             | Trivy server URL (client/server mode) |
| `TRIVY_TIMEOUT`           | `300`                                | Max seconds to wait for scan       |
| `TRIVY_SEVERITY_THRESHOLD`| `CRITICAL,HIGH`                      | Severities that block download     |
| `TRIVY_EXTRA_ARGS`        | *(none)*                             | Extra CLI args for Trivy           |

## CI Pipeline

`.github/workflows/containe-ci.yml` runs on all pushes/PRs: hadolint → docker build → dockle (CIS benchmark) → dive (image efficiency, config in `.dive-ci.yml`) → trivy (vulnerability scan).

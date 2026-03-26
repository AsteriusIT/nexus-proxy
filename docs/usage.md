# Usage Guide

## Overview

Nexus-proxy is a transparent proxy that sits between your package manager clients (or Nexus) and upstream registries. All downloads are forwarded transparently. When a security scanner is active, npm tarball downloads are **scanned on the fly** and blocked if vulnerabilities exceed the severity threshold.

**Workflow:**

1. Point your package manager (or Nexus) at the proxy.
2. Install packages as usual — the proxy forwards everything.
3. If a scanner is active, npm tarballs are scanned before download — blocking ones with critical/high vulnerabilities.

---

## Authentication

If `PROXY_BEARER_TOKEN` is set, all API calls require:

```
Authorization: Bearer <token>
```

All examples below assume auth is configured. Add `-H "Authorization: Bearer $TOKEN"` to your curl commands, or set it once:

```bash
export TOKEN=your-secret-token
alias pcurl='curl -H "Authorization: Bearer $TOKEN"'
```

---

## npm

### Configure npm to use the proxy

In your project's `.npmrc`:

```
registry=http://localhost:8081/repository/npm-group/
```

Or point directly at the proxy for testing:

```
registry=http://localhost:8000/npm/
```

Then install as usual:

```bash
npm install
```

If a scanner is active, each tarball download triggers an on-the-fly scan. Packages that fail the scan return `403` with vulnerability details.

### Browse metadata

```bash
# Unscoped package metadata
pcurl http://localhost:8000/npm/lodash

# Scoped package metadata
pcurl http://localhost:8000/npm/@babel/core
```

Metadata is always proxied transparently. Tarball URLs in the response are rewritten to route through the proxy.

---

## PyPI

### Configure pip

```bash
pip install --index-url http://localhost:8081/repository/pypi-group/simple/ requests
```

Or point directly at the proxy:

```bash
pip install --index-url http://localhost:8000/pypi/simple/ requests
```

### Browse metadata

```bash
# Simple API index
pcurl http://localhost:8000/pypi/simple/

# Package page
pcurl http://localhost:8000/pypi/simple/requests/

# JSON API
pcurl http://localhost:8000/pypi/json/requests
pcurl http://localhost:8000/pypi/json/requests/2.31.0
```

---

## Maven

### Configure Maven

In your `settings.xml`, point the mirror at Nexus (which uses the proxy as upstream):

```xml
<mirror>
  <id>nexus</id>
  <mirrorOf>central</mirrorOf>
  <url>http://localhost:8081/repository/maven-group/</url>
</mirror>
```

### Browse metadata

```bash
# maven-metadata.xml
pcurl http://localhost:8000/maven/metadata/org/apache/commons/commons-lang3/maven-metadata.xml

# POM file
pcurl http://localhost:8000/maven/metadata/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom
```

---

## NuGet

### Configure NuGet

```bash
dotnet nuget add source http://localhost:8081/repository/nuget-group/v3/index.json -n nexus
```

### Browse metadata

```bash
# Service index
pcurl http://localhost:8000/nuget/v3/index.json

# Search
pcurl "http://localhost:8000/nuget/v3/search?q=Newtonsoft"

# Version list
pcurl http://localhost:8000/nuget/v3-flatcontainer/newtonsoft.json/index.json
```

---

## RubyGems

### Configure Bundler

```bash
bundle config mirror.https://rubygems.org http://localhost:8081/repository/rubygems-group/
```

### Browse metadata

```bash
# Gem info
pcurl http://localhost:8000/rubygems/api/v1/gems/rails.json

# Compact index
pcurl http://localhost:8000/rubygems/info/rails
```

---

## Security scanning

### How it works

When a scanner is active, npm tarball downloads are scanned **on the fly**:

1. Client requests a tarball (e.g. `GET /npm/express/-/express-4.18.2.tgz`).
2. The proxy scans the package before streaming the download.
3. If vulnerabilities exceed the threshold, the download is blocked (403).
4. Scan results are cached in memory — subsequent requests for the same package@version skip the scan.
5. If the scanner itself fails (infrastructure issue), the download is **allowed** (fail-open).

For registries other than npm, all downloads are forwarded transparently (no scanning).

### Check which scanner is active

```bash
pcurl http://localhost:8000/admin/scanner
```

Response:

```json
{
  "active": "trivy",
  "available": ["checkmarx", "trivy"]
}
```

### Switch scanner at runtime

```bash
# Enable Trivy
pcurl -X PUT http://localhost:8000/admin/scanner \
  -H "Content-Type: application/json" \
  -d '{"name": "trivy"}'

# Enable Checkmarx
pcurl -X PUT http://localhost:8000/admin/scanner \
  -H "Content-Type: application/json" \
  -d '{"name": "checkmarx"}'

# Disable scanning
pcurl -X PUT http://localhost:8000/admin/scanner \
  -H "Content-Type: application/json" \
  -d '{"name": null}'
```

### Download behavior with active scanner (npm only)

| Scan result | Download behavior |
|-------------|-------------------|
| `passed`    | Allowed (200, streamed) |
| `failed`    | Blocked (403 with vulnerability details) |
| `error`     | Allowed (fail-open) |
| No scanner  | Allowed (transparent forward) |

### Check a cached scan result

```bash
# Unscoped
pcurl http://localhost:8000/npm/scan/express

# Scoped
pcurl http://localhost:8000/npm/scan/@babel/core
```

---

## API reference

The full interactive API documentation is available at:

```
http://localhost:8000/docs     # Swagger UI
http://localhost:8000/redoc    # ReDoc
```

### Endpoints summary

| Method | Path                                            | Description                     |
|--------|------------------------------------------------|---------------------------------|
| `GET`  | `/health`                                       | Health check                    |
| `GET`  | `/admin/scanner`                                | Get active scanner info         |
| `PUT`  | `/admin/scanner`                                | Set active scanner              |
| `GET`  | `/npm/{package}`                                | Proxy npm metadata              |
| `GET`  | `/npm/@{scope}/{package}`                       | Proxy scoped npm metadata       |
| `GET`  | `/npm/{package}/-/{tarball}`                    | Download npm tarball (scanned)  |
| `GET`  | `/npm/@{scope}/{package}/-/{tarball}`           | Download scoped npm tarball     |
| `GET`  | `/npm/scan/{package}`                           | Get cached scan result          |
| `GET`  | `/npm/scan/@{scope}/{package}`                  | Get cached scoped scan result   |
| `GET`  | `/pypi/simple/`                                 | PyPI Simple index               |
| `GET`  | `/pypi/simple/{package}/`                       | PyPI package page               |
| `GET`  | `/pypi/json/{package}`                          | PyPI JSON metadata              |
| `GET`  | `/pypi/files/{path}`                            | Download PyPI file              |
| `GET`  | `/maven/metadata/{path}`                        | Proxy Maven metadata            |
| `GET`  | `/maven/artifact/{path}`                        | Download Maven artifact         |
| `GET`  | `/nuget/v3/index.json`                          | NuGet service index             |
| `GET`  | `/nuget/v3/search`                              | NuGet search                    |
| `GET`  | `/nuget/v3-flatcontainer/{id}/{ver}/{file}`     | Download NuGet package          |
| `GET`  | `/rubygems/api/v1/gems/{name}.json`             | RubyGems metadata               |
| `GET`  | `/rubygems/gems/{filename}`                     | Download gem file               |

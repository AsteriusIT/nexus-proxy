# Deployment Guide

## Prerequisites

- Docker and Docker Compose (recommended), **or** Python 3.12+
- A Sonatype Nexus 3 instance (included in the Docker Compose setup)
- *(Optional)* A security scanner: [Trivy](https://trivy.dev/) binary or [Checkmarx One](https://checkmarx.com/) account

---

## Option 1: Docker Compose (recommended)

This starts Nexus, the proxy, and a Trivy server in a single stack.

### 1. Configure environment

Create a `.env` file at the project root:

```env
# Required if you want to protect the API (recommended)
PROXY_BEARER_TOKEN=your-secret-token

# Security scanner (optional - pick one or leave empty)
# SECURITY_SCANNER=trivy
# SECURITY_SCANNER=checkmarx
```

### 2. Start the stack

```bash
docker-compose up -d
```

Services:

| Service             | URL                    | Description             |
|---------------------|------------------------|-------------------------|
| `nexus`             | `http://localhost:8081` | Sonatype Nexus 3        |
| `nexus-self-proxy`  | container-internal only | The whitelist proxy      |

The proxy waits for Nexus to become healthy before starting.

### 3. Verify

```bash
# Health check
curl http://localhost:8000/health

# OpenAPI docs
open http://localhost:8000/docs
```

### Customizing the Compose file

The default `docker-compose.yaml` uses the pre-built image. To build locally instead:

```yaml
nexus-self-proxy:
  build: .
  # image: rg.fr-par.scw.cloud/asterius-public/nexus-self-proxy:v2.0.0
  environment:
    PROXY_BEARER_TOKEN: ${PROXY_BEARER_TOKEN}
```

---

## Option 2: Docker standalone

```bash
docker build -t nexus-self-proxy .

docker run -d \
  -p 8000:80 \
  -e PROXY_BEARER_TOKEN=your-secret-token \
  --name nexus-self-proxy \
  nexus-self-proxy
```

The container exposes port **80** internally. Map it to whatever host port you need.

---

## Option 3: Run directly with Python

```bash
pip install -r requirements.txt

export PROXY_BEARER_TOKEN=your-secret-token
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

For development with auto-reload:

```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

## Nexus configuration

The proxy sits **in front of** (or alongside) Nexus. You need to configure Nexus so that it uses the proxy as an upstream for its proxy/hosted repositories.

### npm example

1. In Nexus, create an **npm proxy repository** (e.g. `npm-proxy`).
2. Set the **Remote storage URL** to your proxy: `http://nexus-self-proxy:80/npm` (Docker network) or `http://localhost:8000/npm`.
3. If you set `PROXY_BEARER_TOKEN`, configure Nexus to send it as a Bearer token in the HTTP authentication settings of the proxy repository.
4. Create an **npm group repository** that includes both the proxy repository and any hosted repositories.

Repeat a similar setup for PyPI (`/pypi`), Maven (`/maven`), NuGet (`/nuget`), or RubyGems (`/rubygems`).

---

## Security scanner setup

Only one scanner can be active at a time. Set it via the `SECURITY_SCANNER` environment variable or at runtime via `PUT /admin/scanner`.

### Trivy

Trivy runs as a local subprocess. The `trivy` binary must be available inside the container or on the host.

**Adding Trivy to the Docker image:**

```dockerfile
FROM docker.io/python:3.14.3-alpine3.23

# Install Trivy
RUN apk add --no-cache curl && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /selfproxy
COPY ./requirements.txt /selfproxy/requirements.txt
RUN pip install --no-cache-dir pip==26.0.1 && \
    pip install --no-cache-dir --upgrade -r /selfproxy/requirements.txt
COPY ./app /selfproxy/app
RUN adduser -D selfproxy && chown -R selfproxy:selfproxy /selfproxy

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:80/health || exit 1
USER selfproxy
CMD ["fastapi", "run", "app/main.py", "--port", "80"]
```

**Environment variables:**

```env
SECURITY_SCANNER=trivy
# All below are optional
TRIVY_BINARY=trivy                        # Path to binary (default: trivy)
TRIVY_TIMEOUT=300                         # Max scan duration in seconds
TRIVY_SEVERITY_THRESHOLD=CRITICAL,HIGH    # Severities that block download
TRIVY_EXTRA_ARGS=--skip-db-update         # Extra CLI flags
```

**Trivy client/server mode** (optional, for shared DB and faster scans):

```bash
# On a separate host or sidecar container
trivy server --listen 0.0.0.0:4954
```

```env
SECURITY_SCANNER=trivy
TRIVY_SERVER_URL=http://trivy-server:4954
```

### Checkmarx One

Checkmarx requires an active Checkmarx One account with API credentials.

```env
SECURITY_SCANNER=checkmarx
CHECKMARX_BASE_URL=https://eu-2.ast.checkmarx.net
CHECKMARX_IAM_URL=https://eu-2.iam.checkmarx.net
CHECKMARX_TENANT=your-tenant
CHECKMARX_CLIENT_ID=your-client-id
CHECKMARX_CLIENT_SECRET=your-client-secret
CHECKMARX_PROJECT_NAME=nexus-proxy-sca     # optional
CHECKMARX_SCAN_TIMEOUT=300                  # optional
CHECKMARX_SEVERITY_THRESHOLD=CRITICAL,HIGH  # optional
```

### Docker Compose with Trivy (full example)

```yaml
services:
  nexus:
    image: sonatype/nexus3
    container_name: nexus
    volumes:
      - nexus-data:/nexus-data
    ports:
      - "8081:8081"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/service/rest/v1/status"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 60s
    restart: unless-stopped

  nexus-self-proxy:
    build: .  # Use a Dockerfile that includes Trivy
    container_name: nexus-self-proxy
    environment:
      PROXY_BEARER_TOKEN: ${PROXY_BEARER_TOKEN}
      SECURITY_SCANNER: trivy
      TRIVY_SEVERITY_THRESHOLD: CRITICAL,HIGH
    depends_on:
      nexus:
        condition: service_healthy
    restart: unless-stopped

volumes:
  nexus-data:
```

---

## Environment variables reference

### Core

| Variable                  | Default         | Description                                  |
|---------------------------|-----------------|----------------------------------------------|
| `PROXY_BEARER_TOKEN`      | *(none)*        | Bearer token for API auth                    |
| `PROXY_BEARER_TOKEN_FILE` | *(none)*        | File path to read bearer token from          |
| `SECURITY_SCANNER`        | *(none)*        | Active scanner: `trivy`, `checkmarx`, or empty |

### Upstream registries

| Variable                  | Default                              |
|---------------------------|--------------------------------------|
| `NPM_UPSTREAM_REGISTRY`   | `https://registry.npmjs.org`         |
| `PYPI_UPSTREAM_SIMPLE`    | `https://pypi.org/simple`            |
| `PYPI_UPSTREAM_FILES`     | `https://files.pythonhosted.org`     |
| `MAVEN_UPSTREAM_URL`      | `https://repo1.maven.org/maven2`    |
| `NUGET_UPSTREAM_URL`      | `https://api.nuget.org`             |
| `RUBYGEMS_UPSTREAM_URL`   | `https://rubygems.org`              |

### Trivy scanner

| Variable                    | Default          | Description                           |
|-----------------------------|------------------|---------------------------------------|
| `TRIVY_BINARY`              | `trivy`          | Path to the Trivy binary              |
| `TRIVY_SERVER_URL`          | *(none)*         | Trivy server URL (client/server mode) |
| `TRIVY_TIMEOUT`             | `300`            | Max scan duration in seconds          |
| `TRIVY_SEVERITY_THRESHOLD`  | `CRITICAL,HIGH`  | Severities that block download        |
| `TRIVY_EXTRA_ARGS`          | *(none)*         | Extra CLI flags passed to Trivy       |

### Checkmarx scanner

| Variable                         | Default                            | Description                  |
|----------------------------------|------------------------------------|------------------------------|
| `CHECKMARX_BASE_URL`             | `https://eu-2.ast.checkmarx.net`   | API base URL                 |
| `CHECKMARX_IAM_URL`              | `https://eu-2.iam.checkmarx.net`   | IAM base URL                 |
| `CHECKMARX_TENANT`               | *(required)*                       | Tenant / realm name          |
| `CHECKMARX_CLIENT_ID`            | *(required)*                       | OAuth2 client ID             |
| `CHECKMARX_CLIENT_SECRET`        | *(required)*                       | OAuth2 client secret         |
| `CHECKMARX_PROJECT_NAME`         | `nexus-proxy-sca`                  | Project name for scans       |
| `CHECKMARX_SCAN_TIMEOUT`         | `300`                              | Max seconds to wait          |
| `CHECKMARX_SEVERITY_THRESHOLD`   | `CRITICAL,HIGH`                    | Severities that block        |

---

## CI pipeline

The GitHub Actions pipeline (`.github/workflows/containe-ci.yml`) runs on every push and PR:

1. **hadolint** - Dockerfile linting
2. **docker build** - Build the image
3. **dockle** - CIS Benchmark checks
4. **dive** - Image efficiency analysis
5. **trivy** - Container vulnerability scan (this scans the *image*, not packages going through the proxy)

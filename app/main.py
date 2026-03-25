"""Nexus-proxy — transparent whitelisting proxy for package registries.

This FastAPI application sits between developer tools (npm, pip, mvn, dotnet,
bundler) and a Nexus Repository Manager instance.  It enforces a per-package
whitelist: only packages that have been explicitly whitelisted can be
downloaded through the proxy.  After a successful download the whitelist entry
is consumed (Nexus caches the artifact, so no repeated proxy downloads are
needed).

Supported registries
--------------------
- **npm** — ``/npm/...`` (registry.npmjs.org)
- **PyPI** — ``/pypi/...`` (pypi.org / files.pythonhosted.org)
- **Maven** — ``/maven/...`` (repo1.maven.org/maven2)
- **NuGet** — ``/nuget/...`` (api.nuget.org)
- **RubyGems** — ``/rubygems/...`` (rubygems.org)
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, status
from pydantic import BaseModel

from .http_client import close_all
from .routers import maven, npm, nuget, pypi, rubygems

DESCRIPTION = """\
Transparent whitelisting proxy for package registries, designed to work
alongside **Sonatype Nexus Repository Manager**.

## How it works

1. **Whitelist** a package via the `PATCH` endpoint for the relevant registry.
2. **Install** packages normally — your package manager talks to Nexus, which
   routes uncached requests through this proxy.
3. The proxy **checks the whitelist**, streams the artifact from the upstream
   registry, and **removes the whitelist entry** (Nexus caches it from there).

## Supported registries

| Registry   | Prefix        | Upstream                          |
|------------|---------------|-----------------------------------|
| npm        | `/npm`        | registry.npmjs.org                |
| PyPI       | `/pypi`       | pypi.org / files.pythonhosted.org |
| Maven      | `/maven`      | repo1.maven.org/maven2            |
| NuGet      | `/nuget`      | api.nuget.org                     |
| RubyGems   | `/rubygems`   | rubygems.org                      |

## Authentication

All registry endpoints require a **Bearer token** when the `PROXY_BEARER_TOKEN`
(or `PROXY_BEARER_TOKEN_FILE`) environment variable is set.  If neither is
configured the API is open.
"""

TAG_METADATA = [
    {
        "name": "npm",
        "description": "Proxy for the **npm** registry (Node.js / JavaScript). "
        "Supports scoped (`@scope/pkg`) and unscoped packages.",
    },
    {
        "name": "pypi",
        "description": "Proxy for **PyPI** (Python Package Index). Supports the "
        "Simple API (PEP 503), JSON metadata API, and file downloads.",
    },
    {
        "name": "maven",
        "description": "Proxy for **Maven Central** (Java / Kotlin / Android). "
        "Artifacts are identified by `groupId:artifactId`.",
    },
    {
        "name": "nuget",
        "description": "Proxy for the **NuGet** v3 API (.NET / C#). Covers the "
        "service index, search, registration, and flat container endpoints.",
    },
    {
        "name": "rubygems",
        "description": "Proxy for **RubyGems.org** (Ruby). Supports the JSON API, "
        "compact index, and `.gem` file downloads.",
    },
    {
        "name": "healthcheck",
        "description": "Operational health check.",
    },
]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Application lifespan: close all HTTP clients on shutdown."""
    yield
    await close_all()


app = FastAPI(
    title="Nexus Proxy",
    summary="Transparent whitelisting proxy for package registries",
    description=DESCRIPTION,
    version="2.0.0",
    lifespan=lifespan,
    openapi_tags=TAG_METADATA,
    license_info={"name": "MIT"},
)

app.include_router(npm.router)
app.include_router(pypi.router)
app.include_router(maven.router)
app.include_router(nuget.router)
app.include_router(rubygems.router)


class HealthCheck(BaseModel):
    """Response model to validate and return when performing a health check."""

    status: str = "OK"


@app.get(
    "/health",
    tags=["healthcheck"],
    summary="Perform a Health Check",
    response_description="Return HTTP Status Code 200 (OK)",
    status_code=status.HTTP_200_OK,
    response_model=HealthCheck,
)
def get_health() -> HealthCheck:
    """
    ## Perform a Health Check
    Endpoint to perform a healthcheck on. This endpoint can primarily be used Docker
    to ensure a robust container orchestration and management is in place. Other
    services which rely on proper functioning of the API service will not deploy if this
    endpoint returns any other HTTP status code except 200 (OK).
    Returns:
        HealthCheck: Returns a JSON response with the health status
    """
    return HealthCheck(status="OK")

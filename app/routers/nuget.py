"""NuGet v3 registry proxy router.

Proxies the `NuGet v3 API <https://learn.microsoft.com/nuget/api/overview>`_
from https://api.nuget.org.  Download links in the service index and
registration pages are rewritten to route through this proxy.  Package
downloads are forwarded transparently.

Key endpoints
-------------
- **Service index** (``/nuget/v3/index.json``): entry point for NuGet clients,
  with resource URLs rewritten.
- **Flat container** (``/nuget/v3-flatcontainer/...``): package content
  (versions, nupkg, nuspec).
- **Registration** (``/nuget/v3/registration5-semver1/...``): package metadata
  pages with catalog entries.
- **Search** (``/nuget/v3/search``): package search results.

Environment variables
---------------------
NUGET_UPSTREAM_URL : str
    Base URL for the upstream NuGet v3 API
    (default: ``https://api.nuget.org``).
"""

import json
import os

from fastapi import APIRouter, Depends, Query, Request, Response
from starlette.responses import StreamingResponse

from ..auth import require_bearer_token
from ..http_client import get_client

REGISTRY = "nuget"
UPSTREAM_URL = os.environ.get("NUGET_UPSTREAM_URL", "https://api.nuget.org").rstrip("/")

router = APIRouter(
    prefix="/nuget",
    tags=["nuget"],
    dependencies=[Depends(require_bearer_token)],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rewrite_urls(text: str, proxy_base: str) -> str:
    """Replace upstream NuGet URLs with proxy equivalents."""
    return text.replace(UPSTREAM_URL, proxy_base)


# ---------------------------------------------------------------------------
# Service index
# ---------------------------------------------------------------------------


@router.get(
    "/v3/index.json",
    summary="NuGet v3 service index",
    description="Return the NuGet v3 service index with resource URLs rewritten "
    "to route through this proxy.",
)
async def service_index(request: Request):
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.get("/v3/index.json")

    if upstream.status_code != 200:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type="application/json",
        )

    proxy_base = str(request.base_url).rstrip("/") + "/nuget"
    body = _rewrite_urls(upstream.text, proxy_base)

    return Response(content=body, status_code=200, media_type="application/json")


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


@router.get(
    "/v3/search",
    summary="Search for NuGet packages",
    description="Proxy the NuGet search endpoint.  Results are passed through "
    "with download URLs rewritten.",
)
async def search(
    request: Request,
    q: str = Query(default="", description="Search query"),
    skip: int = Query(default=0, ge=0, description="Number of results to skip"),
    take: int = Query(default=20, ge=1, le=100, description="Number of results to return"),
    prerelease: bool = Query(default=False, description="Include pre-release versions"),
):
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.get(
        "/v3/query",
        params={"q": q, "skip": skip, "take": take, "prerelease": str(prerelease).lower()},
    )

    if upstream.status_code != 200:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type="application/json",
        )

    proxy_base = str(request.base_url).rstrip("/") + "/nuget"
    body = _rewrite_urls(upstream.text, proxy_base)

    return Response(content=body, status_code=200, media_type="application/json")


# ---------------------------------------------------------------------------
# Registration (package metadata)
# ---------------------------------------------------------------------------


@router.get(
    "/v3/registration5-semver1/{path:path}",
    summary="Get NuGet package registration",
    description="Fetch package registration metadata (catalog pages, dependency info) "
    "from the upstream NuGet registry. URLs are rewritten to route through the proxy.",
)
async def registration(path: str, request: Request):
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.get(f"/v3/registration5-semver1/{path}")

    if upstream.status_code != 200:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type="application/json",
        )

    proxy_base = str(request.base_url).rstrip("/") + "/nuget"
    body = _rewrite_urls(upstream.text, proxy_base)

    return Response(content=body, status_code=200, media_type="application/json")


# ---------------------------------------------------------------------------
# Flat container — version list & nuspec
# ---------------------------------------------------------------------------


@router.get(
    "/v3-flatcontainer/{package_id}/index.json",
    summary="List package versions",
    description="Return the list of available versions for a NuGet package.",
)
async def list_versions(package_id: str):
    lower_id = package_id.lower()
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.get(f"/v3-flatcontainer/{lower_id}/index.json")

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type="application/json",
    )


@router.get(
    "/v3-flatcontainer/{package_id}/{version}/{package_id2}.nuspec",
    summary="Get package nuspec",
    description="Fetch the ``.nuspec`` manifest for a specific package version.",
)
async def get_nuspec(package_id: str, version: str, package_id2: str):
    lower_id = package_id.lower()
    lower_ver = version.lower()
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.get(
        f"/v3-flatcontainer/{lower_id}/{lower_ver}/{lower_id}.nuspec"
    )

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type="application/xml",
    )


# ---------------------------------------------------------------------------
# Flat container — nupkg download (streamed)
# ---------------------------------------------------------------------------


@router.get(
    "/v3-flatcontainer/{package_id}/{version}/{filename}",
    summary="Download a NuGet package (.nupkg)",
    description="Stream a ``.nupkg`` file from the upstream NuGet registry.",
)
async def download_nupkg(package_id: str, version: str, filename: str):
    lower_id = package_id.lower()
    lower_ver = version.lower()

    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.send(
        client.build_request(
            "GET",
            f"/v3-flatcontainer/{lower_id}/{lower_ver}/{filename}",
        ),
        stream=True,
    )

    if upstream.status_code != 200:
        body = await upstream.aread()
        await upstream.aclose()
        return Response(content=body, status_code=upstream.status_code)

    async def stream():
        try:
            async for chunk in upstream.aiter_bytes(chunk_size=64 * 1024):
                yield chunk
        finally:
            await upstream.aclose()

    return StreamingResponse(
        stream(),
        status_code=200,
        media_type="application/octet-stream",
        headers={"content-length": upstream.headers.get("content-length", "")},
    )

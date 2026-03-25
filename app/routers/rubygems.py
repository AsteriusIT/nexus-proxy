"""RubyGems registry proxy router.

Proxies the `RubyGems.org API <https://guides.rubygems.org/rubygems-org-api/>`_
from https://rubygems.org.  Gem downloads are gated by an in-memory whitelist.

Key endpoints
-------------
- **Gem info** (``/rubygems/api/v1/gems/{name}.json``): JSON metadata for a gem.
- **Versions** (``/rubygems/api/v1/versions/{name}.json``): all versions of a gem.
- **Dependencies** (``/rubygems/api/v1/dependencies``): dependency resolution.
- **Gem download** (``/rubygems/gems/{name}-{version}.gem``): whitelist-gated.

Environment variables
---------------------
RUBYGEMS_UPSTREAM_URL : str
    Base URL of the upstream RubyGems registry
    (default: ``https://rubygems.org``).
"""

import os
import re

from fastapi import APIRouter, Depends, Query, Request, Response
from starlette.responses import StreamingResponse

from .. import whitelist
from ..auth import require_bearer_token
from ..http_client import get_client

REGISTRY = "rubygems"
UPSTREAM_URL = os.environ.get("RUBYGEMS_UPSTREAM_URL", "https://rubygems.org").rstrip("/")

router = APIRouter(
    prefix="/rubygems",
    tags=["rubygems"],
    dependencies=[Depends(require_bearer_token)],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_gem_name(filename: str) -> str:
    """Extract the gem name from a filename like ``rails-7.1.3.gem``.

    Gem filenames follow the pattern ``name-version.gem`` where version starts
    with a digit.  Names can contain dashes (e.g. ``net-http``).
    """
    # Remove .gem suffix
    stem = filename.removesuffix(".gem")
    # Split on last dash-followed-by-digit: "net-http-0.4.1" → "net-http"
    match = re.match(r"^(.+?)-\d", stem)
    return match.group(1) if match else stem


# ---------------------------------------------------------------------------
# Metadata endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/gems/{gem_name}.json",
    summary="Get gem metadata",
    description="Fetch JSON metadata for a RubyGem from the upstream registry.",
)
async def gem_info(gem_name: str):
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.get(f"/api/v1/gems/{gem_name}.json")

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type="application/json",
    )


@router.get(
    "/api/v1/versions/{gem_name}.json",
    summary="List gem versions",
    description="Fetch the version history for a RubyGem.",
)
async def gem_versions(gem_name: str):
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.get(f"/api/v1/versions/{gem_name}.json")

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type="application/json",
    )


@router.get(
    "/api/v1/dependencies",
    summary="Resolve gem dependencies",
    description="Fetch dependency information for one or more gems. "
    "Pass gem names as a comma-separated ``gems`` query parameter.",
)
async def gem_dependencies(gems: str = Query(description="Comma-separated gem names")):
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.get("/api/v1/dependencies", params={"gems": gems})

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "application/octet-stream"),
    )


# ---------------------------------------------------------------------------
# Gem info endpoint (compact index)
# ---------------------------------------------------------------------------


@router.get(
    "/info/{gem_name}",
    summary="Compact index info",
    description="Fetch compact index info for a gem (used by modern Bundler).",
)
async def compact_index_info(gem_name: str):
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.get(f"/info/{gem_name}")

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "text/plain"),
    )


@router.get(
    "/versions",
    summary="Compact index versions",
    description="Fetch the compact index versions list (used by modern Bundler).",
)
async def compact_index_versions():
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.get("/versions")

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "text/plain"),
    )


# ---------------------------------------------------------------------------
# Gem download (streamed, whitelist-gated)
# ---------------------------------------------------------------------------


@router.get(
    "/gems/{filename}",
    summary="Download a gem file",
    description="Stream a ``.gem`` file from the upstream RubyGems registry. "
    "The gem must be whitelisted first by name. After a successful download "
    "the whitelist entry is consumed.",
)
async def download_gem(filename: str):
    gem_name = _extract_gem_name(filename)

    if not whitelist.is_whitelisted(REGISTRY, None, gem_name):
        return Response(content="Forbidden", status_code=403)

    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.send(
        client.build_request("GET", f"/gems/{filename}"), stream=True
    )

    if upstream.status_code != 200:
        body = await upstream.aread()
        await upstream.aclose()
        return Response(content=body, status_code=upstream.status_code)

    whitelist.remove(REGISTRY, None, gem_name)

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


# ---------------------------------------------------------------------------
# Whitelist management
# ---------------------------------------------------------------------------


@router.patch(
    "/{gem_name}",
    summary="Whitelist a RubyGem",
    description="Add a RubyGem to the download whitelist by name.",
)
async def whitelist_rubygem(gem_name: str):
    whitelist.add(REGISTRY, None, gem_name)
    return {"whitelisted": gem_name}

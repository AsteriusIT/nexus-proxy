"""RubyGems registry proxy router.

Proxies the `RubyGems.org API <https://guides.rubygems.org/rubygems-org-api/>`_
from https://rubygems.org.  Gem downloads are forwarded transparently.

Key endpoints
-------------
- **Gem info** (``/rubygems/api/v1/gems/{name}.json``): JSON metadata for a gem.
- **Versions** (``/rubygems/api/v1/versions/{name}.json``): all versions of a gem.
- **Dependencies** (``/rubygems/api/v1/dependencies``): dependency resolution.
- **Gem download** (``/rubygems/gems/{name}-{version}.gem``): streamed from upstream.

Environment variables
---------------------
RUBYGEMS_UPSTREAM_URL : str
    Base URL of the upstream RubyGems registry
    (default: ``https://rubygems.org``).
"""

import logging
import os
import re

from fastapi import APIRouter, Depends, Query, Request, Response
from starlette.responses import JSONResponse, StreamingResponse

from .. import scanner
from ..auth import require_bearer_token
from ..http_client import get_client
from ..scanner import ScanResult, ScanStatus

logger = logging.getLogger(__name__)

REGISTRY = "rubygems"
UPSTREAM_URL = os.environ.get("RUBYGEMS_UPSTREAM_URL", "https://rubygems.org").rstrip("/")

router = APIRouter(
    prefix="/rubygems",
    tags=["rubygems"],
    dependencies=[Depends(require_bearer_token)],
)

# In-memory cache of scan results, keyed by "gem@version"
_scan_cache: dict[str, ScanResult] = {}

# Gem filename pattern: name-version.gem (version starts with a digit)
_GEM_RE = re.compile(r"^(.+?)-(\d[^-]*?)\.gem$")


def _extract_gem_name_version(filename: str) -> tuple[str, str]:
    """Extract gem name and version from ``name-version.gem``."""
    m = _GEM_RE.match(filename)
    if m:
        return m.group(1), m.group(2)
    return filename.removesuffix(".gem"), "unknown"


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
# Gem download (streamed)
# ---------------------------------------------------------------------------


@router.get(
    "/gems/{filename}",
    summary="Download a gem file",
    description="Stream a ``.gem`` file from the upstream RubyGems registry. "
    "If a security scanner is active, the gem is scanned on the fly.",
)
async def download_gem(filename: str):
    gem_name, version = _extract_gem_name_version(filename)
    logger.info("[rubygems] Download requested: %s@%s (%s)", gem_name, version, filename)

    # Scan if a scanner is active
    active_scanner = scanner.get_active()
    if active_scanner is not None:
        key = f"{gem_name}@{version}"
        result = _scan_cache.get(key)

        if result is not None:
            logger.info("[rubygems] [SCAN] Cache hit for %s — status=%s", key, result.status.value)
        else:
            logger.info("[rubygems] [SCAN] Scanning %s with '%s'...", key, scanner.get_active_name())
            result = await active_scanner.scan_package(gem_name, version, "rubygems")
            _scan_cache[key] = result

        if result.status == ScanStatus.FAILED:
            logger.warning("[rubygems] [BLOCKED] Download of %s blocked — %s", key, result.summary)
            return JSONResponse(
                content={
                    "error": "Security scan failed — download blocked",
                    "detail": result.summary,
                    "vulnerabilities": [v.model_dump() for v in result.vulnerabilities],
                },
                status_code=403,
            )

        if result.status == ScanStatus.ERROR:
            logger.warning("[rubygems] [SCAN] Scanner error for %s — allowing download (fail-open): %s", key, result.summary)

    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.send(
        client.build_request("GET", f"/gems/{filename}"), stream=True
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

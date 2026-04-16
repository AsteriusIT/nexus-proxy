"""PyPI registry proxy router.

Proxies the `PEP 503 Simple API <https://peps.python.org/pep-0503/>`_ from
https://pypi.org and rewrites download URLs so that packages are fetched
through this proxy.  Downloads are forwarded transparently.

How it works
------------
1. ``pip`` requests ``/pypi/simple/{package}/`` — the proxy fetches the page
   from upstream PyPI and rewrites every ``files.pythonhosted.org`` link to
   point at ``/pypi/files/...``.
2. ``pip`` then requests the file through the proxy (``/pypi/files/...``),
   which is streamed from upstream.

Environment variables
---------------------
PYPI_UPSTREAM_SIMPLE : str
    Base URL for the Simple API (default: ``https://pypi.org/simple``).
PYPI_UPSTREAM_FILES : str
    Base URL where package files are hosted
    (default: ``https://files.pythonhosted.org``).
"""

import logging
import os
import re

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import JSONResponse, StreamingResponse

from .. import scanner
from ..auth import require_bearer_token
from ..http_client import get_client
from ..scanner import ScanResult, ScanStatus

logger = logging.getLogger(__name__)

REGISTRY = "pypi"
UPSTREAM_SIMPLE = os.environ.get("PYPI_UPSTREAM_SIMPLE", "https://pypi.org/simple").rstrip("/")
UPSTREAM_FILES = os.environ.get("PYPI_UPSTREAM_FILES", "https://files.pythonhosted.org").rstrip("/")

router = APIRouter(
    prefix="/pypi",
    tags=["pypi"],
    dependencies=[Depends(require_bearer_token)],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# In-memory cache of scan results, keyed by "package@version"
_scan_cache: dict[str, ScanResult] = {}


def _normalize_name(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of [-_.] → single dash."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _extract_pypi_name_version(filename: str) -> tuple[str, str]:
    """Extract package name and version from a PyPI filename.

    Handles sdists (``name-1.0.0.tar.gz``) and wheels
    (``name-1.0.0-cp39-cp39-linux.whl``).
    """
    # Strip common archive extensions
    base = filename
    for ext in (".tar.gz", ".tar.bz2", ".zip", ".whl", ".egg"):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break

    # Wheels: name-version-pythontag-abitag-platformtag
    # Sdists: name-version
    # Split on '-' and find the version boundary (first segment starting with digit)
    parts = base.split("-")
    for i, part in enumerate(parts):
        if i > 0 and part and part[0].isdigit():
            name = "-".join(parts[:i])
            version = parts[i]
            return _normalize_name(name), version

    return _normalize_name(base), "unknown"


def _rewrite_file_urls(html: str, proxy_base_url: str) -> str:
    """Replace ``files.pythonhosted.org`` links with proxy links."""
    return html.replace(UPSTREAM_FILES, proxy_base_url + "/files")


# ---------------------------------------------------------------------------
# Simple API (metadata)
# ---------------------------------------------------------------------------


@router.get(
    "/simple/",
    summary="Simple API index",
    description="Return the full Simple API package index from the upstream PyPI registry.",
)
async def simple_index(request: Request):
    client = get_client(UPSTREAM_SIMPLE, name=f"{REGISTRY}-simple")
    upstream = await client.get("/")

    if upstream.status_code != 200:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "text/html"),
        )

    proxy_base = str(request.base_url).rstrip("/") + "/pypi"
    html = upstream.text
    # No URL rewriting needed for the index — it only contains relative links

    return Response(content=html, status_code=200, media_type="text/html")


@router.get(
    "/simple/{package_name}/",
    summary="Simple API package page",
    description="Fetch the Simple API page for a specific package. Download links "
    "in the response are rewritten to route through this proxy.",
)
async def simple_package(package_name: str, request: Request):
    normalized = _normalize_name(package_name)
    client = get_client(UPSTREAM_SIMPLE, name=f"{REGISTRY}-simple")
    upstream = await client.get(f"/{normalized}/")

    if upstream.status_code != 200:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "text/html"),
        )

    proxy_base = str(request.base_url).rstrip("/") + "/pypi"
    html = _rewrite_file_urls(upstream.text, proxy_base)

    return Response(content=html, status_code=200, media_type="text/html")


# ---------------------------------------------------------------------------
# JSON API (metadata)
# ---------------------------------------------------------------------------


@router.get(
    "/json/{package_name}",
    summary="Get package metadata (JSON)",
    description="Fetch full JSON metadata for a PyPI package, including all versions "
    "and download URLs. File URLs are rewritten to route through the proxy.",
)
async def json_metadata(package_name: str, request: Request):
    # The JSON API lives on pypi.org (not /simple)
    client = get_client("https://pypi.org", name=f"{REGISTRY}-json")
    upstream = await client.get(f"/pypi/{package_name}/json")

    if upstream.status_code != 200:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type="application/json",
        )

    proxy_base = str(request.base_url).rstrip("/") + "/pypi"
    body = upstream.text.replace(UPSTREAM_FILES, proxy_base + "/files")

    return Response(content=body, status_code=200, media_type="application/json")


@router.get(
    "/json/{package_name}/{version}",
    summary="Get package version metadata (JSON)",
    description="Fetch JSON metadata for a specific version of a PyPI package.",
)
async def json_version_metadata(package_name: str, version: str, request: Request):
    client = get_client("https://pypi.org", name=f"{REGISTRY}-json")
    upstream = await client.get(f"/pypi/{package_name}/{version}/json")

    if upstream.status_code != 200:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type="application/json",
        )

    proxy_base = str(request.base_url).rstrip("/") + "/pypi"
    body = upstream.text.replace(UPSTREAM_FILES, proxy_base + "/files")

    return Response(content=body, status_code=200, media_type="application/json")


# ---------------------------------------------------------------------------
# File download (streamed)
# ---------------------------------------------------------------------------


@router.get(
    "/files/{file_path:path}",
    summary="Download a package file",
    description="Stream a package file (wheel, sdist, etc.) from upstream PyPI. "
    "If a security scanner is active, the package is scanned on the fly.",
)
async def download_file(file_path: str):
    filename = file_path.rsplit("/", 1)[-1]
    package_name, version = _extract_pypi_name_version(filename)
    logger.info("[pypi] Download requested: %s@%s (%s)", package_name, version, filename)

    # Scan if a scanner is active
    active_scanner = scanner.get_active()
    if active_scanner is not None:
        key = f"{package_name}@{version}"
        result = _scan_cache.get(key)

        if result is not None:
            logger.info("[pypi] [SCAN] Cache hit for %s — status=%s", key, result.status.value)
        else:
            logger.info("[pypi] [SCAN] Scanning %s with '%s'...", key, scanner.get_active_name())
            result = await active_scanner.scan_package(package_name, version, "pypi")
            _scan_cache[key] = result

        if result.status == ScanStatus.FAILED:
            logger.warning("[pypi] [BLOCKED] Download of %s blocked — %s", key, result.summary)
            return JSONResponse(
                content={
                    "error": "Security scan failed — download blocked",
                    "detail": result.summary,
                    "vulnerabilities": [v.model_dump() for v in result.vulnerabilities],
                },
                status_code=403,
            )

        if result.status == ScanStatus.ERROR:
            logger.warning("[pypi] [SCAN] Scanner error for %s — allowing download (fail-open): %s", key, result.summary)

    client = get_client(UPSTREAM_FILES, name=f"{REGISTRY}-files")
    upstream = await client.send(
        client.build_request("GET", f"/{file_path}"), stream=True
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

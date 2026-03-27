"""npm registry proxy router.

Proxies metadata from https://registry.npmjs.org and rewrites tarball URLs so
that downloads are routed through this proxy.  Tarball downloads are forwarded
transparently unless a security scanner is active — in which case the package
is scanned on the fly and blocked if vulnerabilities exceed the threshold.

Environment variables
---------------------
NPM_UPSTREAM_REGISTRY : str
    Base URL of the upstream npm registry (default: ``https://registry.npmjs.org``).
"""

import json
import logging
import os

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import JSONResponse, StreamingResponse

from .. import scanner
from ..auth import require_bearer_token
from ..http_client import get_client
from ..scanner import ScanResult, ScanStatus

logger = logging.getLogger(__name__)

REGISTRY = "npm"
UPSTREAM_URL = os.environ.get("NPM_UPSTREAM_REGISTRY", "https://registry.npmjs.org").rstrip("/")

router = APIRouter(
    prefix="/npm",
    tags=["npm"],
    dependencies=[Depends(require_bearer_token)],
)

# In-memory cache of scan results, keyed by "scope/package@version"
_scan_cache: dict[str, ScanResult] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pkg_key(scope: str | None, package_name: str, version: str) -> str:
    """Build a cache key for scan results."""
    return f"{scope or '_'}/{package_name}@{version}"


def _registry_path(scope: str | None, package_name: str) -> str:
    return f"/@{scope}/{package_name}" if scope else f"/{package_name}"


def _rewrite_tarball_urls(metadata: dict, proxy_base_url: str) -> dict:
    """Replace upstream tarball URLs with our proxy URL."""
    raw = json.dumps(metadata)
    raw = raw.replace(UPSTREAM_URL, proxy_base_url)
    return json.loads(raw)


def _full_name(scope: str | None, package_name: str) -> str:
    """Return the full npm package name (``@scope/name`` or ``name``)."""
    return f"@{scope}/{package_name}" if scope else package_name


def _extract_version(tarball_filename: str, package_name: str) -> str:
    """Extract version from tarball filename like ``express-4.18.2.tgz``."""
    prefix = f"{package_name}-"
    if tarball_filename.startswith(prefix) and tarball_filename.endswith(".tgz"):
        return tarball_filename[len(prefix):-4]
    return "unknown"


# ---------------------------------------------------------------------------
# Metadata endpoints
# ---------------------------------------------------------------------------


async def _proxy_metadata(request: Request, scope: str | None, package_name: str):
    full_name = _full_name(scope, package_name)
    logger.debug("[npm] Fetching metadata for %s", full_name)
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    path = _registry_path(scope, package_name)

    upstream = await client.get(path)

    if upstream.status_code != 200:
        logger.warning("[npm] Upstream returned %d for metadata of %s", upstream.status_code, full_name)
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )

    metadata = upstream.json()
    proxy_base_url = str(request.base_url).rstrip("/") + "/npm"
    metadata = _rewrite_tarball_urls(metadata, proxy_base_url)
    logger.debug("[npm] Metadata for %s rewritten and served", full_name)

    return Response(
        content=json.dumps(metadata),
        status_code=200,
        media_type="application/json",
    )


@router.get(
    "/{package_name}",
    summary="Get unscoped package metadata",
    description="Fetch metadata for an unscoped npm package from the upstream registry. "
    "Tarball URLs in the response are rewritten to route through this proxy.",
)
async def get_package_metadata(package_name: str, request: Request):
    return await _proxy_metadata(request, scope=None, package_name=package_name)


@router.get(
    "/@{scope}/{package_name}",
    summary="Get scoped package metadata",
    description="Fetch metadata for a scoped npm package (e.g. ``@scope/name``) from the "
    "upstream registry. Tarball URLs are rewritten to route through this proxy.",
)
async def get_scoped_package_metadata(scope: str, package_name: str, request: Request):
    return await _proxy_metadata(request, scope=scope, package_name=package_name)


# ---------------------------------------------------------------------------
# Tarball endpoints (streamed, optionally scanned)
# ---------------------------------------------------------------------------


async def _proxy_tarball(scope: str | None, package_name: str, tarball_filename: str):
    full_name = _full_name(scope, package_name)
    version = _extract_version(tarball_filename, package_name)
    logger.info("[npm] Download requested: %s@%s (%s)", full_name, version, tarball_filename)

    # If a scanner is active, scan on the fly (with caching)
    active_scanner = scanner.get_active()
    if active_scanner is not None:
        scanner_name = scanner.get_active_name()
        key = _pkg_key(scope, package_name, version)
        result = _scan_cache.get(key)

        if result is not None:
            logger.info(
                "[npm] [SCAN] Cache hit for %s@%s — status=%s (scanner=%s)",
                full_name, version, result.status.value, result.scanner,
            )
        else:
            logger.info(
                "[npm] [SCAN] Scanning %s@%s with scanner '%s' before download...",
                full_name, version, scanner_name,
            )
            result = await active_scanner.scan_npm_package(full_name, version)
            _scan_cache[key] = result

            if result.status == ScanStatus.PASSED:
                logger.info(
                    "[npm] [SCAN] PASSED — %s@%s — %s",
                    full_name, version, result.summary,
                )
            elif result.status == ScanStatus.FAILED:
                logger.warning(
                    "[npm] [SCAN] FAILED — %s@%s — %s",
                    full_name, version, result.summary,
                )
                for v in result.vulnerabilities:
                    logger.warning(
                        "[npm] [SCAN]   %s %s in %s@%s — %s",
                        v.severity, v.id, v.package_name, v.package_version, v.description[:120],
                    )
            elif result.status == ScanStatus.ERROR:
                logger.error(
                    "[npm] [SCAN] ERROR — %s@%s — %s",
                    full_name, version, result.summary,
                )

        if result.status == ScanStatus.FAILED:
            logger.warning(
                "[npm] [BLOCKED] Download of %s@%s blocked — %d vulnerabilities exceed threshold",
                full_name, version, len(result.vulnerabilities),
            )
            return JSONResponse(
                content={
                    "error": "Security scan failed — download blocked",
                    "detail": result.summary,
                    "scan_id": result.scan_id,
                    "vulnerabilities": [v.model_dump() for v in result.vulnerabilities],
                },
                status_code=403,
            )

        if result.status == ScanStatus.ERROR:
            logger.warning(
                "[npm] [SCAN] Scanner error for %s@%s — allowing download (fail-open): %s",
                full_name, version, result.summary,
            )
    else:
        logger.debug("[npm] No active scanner — forwarding %s@%s without scan", full_name, version)

    logger.info("[npm] [ALLOWED] Streaming %s@%s from upstream", full_name, version)

    client = get_client(UPSTREAM_URL, name=REGISTRY)
    path = _registry_path(scope, package_name)
    url = f"{path}/-/{tarball_filename}"

    upstream = await client.send(client.build_request("GET", url), stream=True)

    if upstream.status_code != 200:
        body = await upstream.aread()
        await upstream.aclose()
        logger.error(
            "[npm] Upstream returned %d for tarball %s@%s",
            upstream.status_code, full_name, version,
        )
        return Response(content=body, status_code=upstream.status_code)

    content_length = upstream.headers.get("content-length", "unknown")
    logger.info("[npm] Streaming %s (%s bytes) to client", tarball_filename, content_length)

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


@router.get(
    "/{package_name}/-/{tarball_filename}",
    summary="Download unscoped package tarball",
    description="Stream a tarball for an unscoped npm package. If a security scanner is "
    "active, the package is scanned on the fly — downloads are blocked if "
    "vulnerabilities exceed the severity threshold.",
)
async def get_package_tarball(package_name: str, tarball_filename: str):
    return await _proxy_tarball(None, package_name, tarball_filename)


@router.get(
    "/@{scope}/{package_name}/-/{tarball_filename}",
    summary="Download scoped package tarball",
    description="Stream a tarball for a scoped npm package. If a security scanner is "
    "active, the package is scanned before download.",
)
async def get_scoped_package_tarball(
    scope: str, package_name: str, tarball_filename: str
):
    return await _proxy_tarball(scope, package_name, tarball_filename)


# ---------------------------------------------------------------------------
# Scan result inspection
# ---------------------------------------------------------------------------


@router.get(
    "/scan/{package_name}",
    summary="Get scan result for an unscoped package",
    description="Retrieve the cached security scan result for an unscoped npm package.",
)
async def get_scan_result(package_name: str):
    # Return the most recent scan for this package (any version)
    prefix = f"_/{package_name}@"
    for key, result in _scan_cache.items():
        if key.startswith(prefix):
            return result.model_dump()
    return Response(content="No scan result found", status_code=404)


@router.get(
    "/scan/@{scope}/{package_name}",
    summary="Get scan result for a scoped package",
    description="Retrieve the cached security scan result for a scoped npm package.",
)
async def get_scoped_scan_result(scope: str, package_name: str):
    prefix = f"{scope}/{package_name}@"
    for key, result in _scan_cache.items():
        if key.startswith(prefix):
            return result.model_dump()
    return Response(content="No scan result found", status_code=404)

"""npm registry proxy router.

Proxies metadata from https://registry.npmjs.org and rewrites tarball URLs so
that downloads are routed through this proxy.  Tarball downloads are gated by
an in-memory whitelist; after a successful download the entry is removed
(Nexus caches the artifact).

When a security scanner is active, whitelisting a package triggers an SCA scan.
The scan result is cached and checked at download time — packages that fail the
scan are blocked.

Environment variables
---------------------
NPM_UPSTREAM_REGISTRY : str
    Base URL of the upstream npm registry (default: ``https://registry.npmjs.org``).
"""

import json
import logging
import os

from fastapi import APIRouter, Depends, Query, Request, Response
from starlette.responses import JSONResponse, StreamingResponse

from .. import scanner, whitelist
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

# In-memory cache of scan results, keyed by "scope/package" or "_/package"
_scan_results: dict[str, ScanResult] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pkg_key(scope: str | None, package_name: str) -> str:
    """Build a cache key for scan results."""
    return f"{scope or '_'}/{package_name}"


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


# ---------------------------------------------------------------------------
# Metadata endpoints
# ---------------------------------------------------------------------------


async def _proxy_metadata(request: Request, scope: str | None, package_name: str):
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    path = _registry_path(scope, package_name)

    upstream = await client.get(path)

    if upstream.status_code != 200:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )

    metadata = upstream.json()
    proxy_base_url = str(request.base_url).rstrip("/") + "/npm"
    metadata = _rewrite_tarball_urls(metadata, proxy_base_url)

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
# Tarball endpoints (streamed)
# ---------------------------------------------------------------------------


async def _proxy_tarball(scope: str | None, package_name: str, tarball_filename: str):
    if not whitelist.is_whitelisted(REGISTRY, scope, package_name):
        return Response(content="Forbidden", status_code=403)

    # Check scan result if a scanner is active
    active_scanner = scanner.get_active()
    if active_scanner is not None:
        key = _pkg_key(scope, package_name)
        result = _scan_results.get(key)

        if result is None:
            return JSONResponse(
                content={
                    "error": "Security scan not yet performed",
                    "detail": f"Package {_full_name(scope, package_name)} is whitelisted but "
                    "has not been scanned. Re-whitelist the package to trigger a scan.",
                },
                status_code=403,
            )

        if result.status == ScanStatus.PENDING:
            return JSONResponse(
                content={
                    "error": "Security scan in progress",
                    "detail": f"Scan for {_full_name(scope, package_name)} is still running. "
                    "Retry later.",
                    "scan_id": result.scan_id,
                },
                status_code=202,
            )

        if result.status == ScanStatus.FAILED:
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
                "Scan error for %s — allowing download: %s",
                _full_name(scope, package_name),
                result.summary,
            )
            # On scanner error, allow download (fail-open to not block development)

    client = get_client(UPSTREAM_URL, name=REGISTRY)
    path = _registry_path(scope, package_name)
    url = f"{path}/-/{tarball_filename}"

    upstream = await client.send(client.build_request("GET", url), stream=True)

    if upstream.status_code != 200:
        body = await upstream.aread()
        await upstream.aclose()
        return Response(content=body, status_code=upstream.status_code)

    # Remove from whitelist and scan cache — Nexus will cache the tarball
    whitelist.remove(REGISTRY, scope, package_name)
    _scan_results.pop(_pkg_key(scope, package_name), None)

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
    description="Stream a tarball for an unscoped npm package. The package must be "
    "whitelisted first via the PATCH endpoint. If a security scanner is active, "
    "the package must also pass the scan. After a successful download "
    "the package is removed from the whitelist.",
)
async def get_package_tarball(package_name: str, tarball_filename: str):
    return await _proxy_tarball(None, package_name, tarball_filename)


@router.get(
    "/@{scope}/{package_name}/-/{tarball_filename}",
    summary="Download scoped package tarball",
    description="Stream a tarball for a scoped npm package. The package must be "
    "whitelisted and pass a security scan (if active).",
)
async def get_scoped_package_tarball(
    scope: str, package_name: str, tarball_filename: str
):
    return await _proxy_tarball(scope, package_name, tarball_filename)


# ---------------------------------------------------------------------------
# Whitelist management
# ---------------------------------------------------------------------------


async def _whitelist_and_scan(
    scope: str | None, package_name: str, version: str = "latest"
) -> dict:
    """Add a package to the whitelist and trigger a security scan if active."""
    whitelist.add(REGISTRY, scope, package_name)
    full_name = _full_name(scope, package_name)
    key = _pkg_key(scope, package_name)

    active_scanner = scanner.get_active()
    if active_scanner is None:
        return {"whitelisted": full_name, "scan": None}

    # Mark as pending immediately
    _scan_results[key] = ScanResult(
        status=ScanStatus.PENDING,
        scanner=scanner.get_active_name() or "",
        summary="Scan in progress…",
    )

    # Run scan (blocking — the client waits for the result)
    result = await active_scanner.scan_npm_package(full_name, version)
    _scan_results[key] = result

    logger.info("Scan result for %s: %s — %s", full_name, result.status.value, result.summary)

    return {
        "whitelisted": full_name,
        "scan": {
            "status": result.status.value,
            "scanner": result.scanner,
            "scan_id": result.scan_id,
            "summary": result.summary,
        },
    }


@router.patch(
    "/{package_name}",
    summary="Whitelist an unscoped package",
    description="Add an unscoped npm package to the download whitelist. "
    "If a security scanner is active, the package is scanned automatically — "
    "the response includes the scan result. Use the ``version`` query "
    "parameter to scan a specific version (defaults to ``latest``).",
)
async def whitelist_package(
    package_name: str,
    version: str = Query(default="latest", description="Version to scan (e.g. ``4.17.21``)"),
):
    return await _whitelist_and_scan(None, package_name, version)


@router.patch(
    "/@{scope}/{package_name}",
    summary="Whitelist a scoped package",
    description="Add a scoped npm package (e.g. ``@scope/name``) to the download "
    "whitelist and trigger a security scan if a scanner is active.",
)
async def whitelist_scoped_package(
    scope: str,
    package_name: str,
    version: str = Query(default="latest", description="Version to scan"),
):
    return await _whitelist_and_scan(scope, package_name, version)


# ---------------------------------------------------------------------------
# Scan result inspection
# ---------------------------------------------------------------------------


@router.get(
    "/scan/{package_name}",
    summary="Get scan result for an unscoped package",
    description="Retrieve the cached security scan result for a whitelisted "
    "unscoped npm package.",
)
async def get_scan_result(package_name: str):
    key = _pkg_key(None, package_name)
    result = _scan_results.get(key)
    if result is None:
        return Response(content="No scan result found", status_code=404)
    return result.model_dump()


@router.get(
    "/scan/@{scope}/{package_name}",
    summary="Get scan result for a scoped package",
    description="Retrieve the cached security scan result for a whitelisted "
    "scoped npm package.",
)
async def get_scoped_scan_result(scope: str, package_name: str):
    key = _pkg_key(scope, package_name)
    result = _scan_results.get(key)
    if result is None:
        return Response(content="No scan result found", status_code=404)
    return result.model_dump()

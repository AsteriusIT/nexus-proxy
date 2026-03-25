"""npm registry proxy router.

Proxies metadata from https://registry.npmjs.org and rewrites tarball URLs so
that downloads are routed through this proxy.  Tarball downloads are gated by
an in-memory whitelist; after a successful download the entry is removed
(Nexus caches the artifact).

Environment variables
---------------------
NPM_UPSTREAM_REGISTRY : str
    Base URL of the upstream npm registry (default: ``https://registry.npmjs.org``).
"""

import json
import os

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import StreamingResponse

from .. import whitelist
from ..auth import require_bearer_token
from ..http_client import get_client

REGISTRY = "npm"
UPSTREAM_URL = os.environ.get("NPM_UPSTREAM_REGISTRY", "https://registry.npmjs.org").rstrip("/")

router = APIRouter(
    prefix="/npm",
    tags=["npm"],
    dependencies=[Depends(require_bearer_token)],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _registry_path(scope: str | None, package_name: str) -> str:
    return f"/@{scope}/{package_name}" if scope else f"/{package_name}"


def _rewrite_tarball_urls(metadata: dict, proxy_base_url: str) -> dict:
    """Replace upstream tarball URLs with our proxy URL."""
    raw = json.dumps(metadata)
    raw = raw.replace(UPSTREAM_URL, proxy_base_url)
    return json.loads(raw)


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

    client = get_client(UPSTREAM_URL, name=REGISTRY)
    path = _registry_path(scope, package_name)
    url = f"{path}/-/{tarball_filename}"

    upstream = await client.send(client.build_request("GET", url), stream=True)

    if upstream.status_code != 200:
        body = await upstream.aread()
        await upstream.aclose()
        return Response(content=body, status_code=upstream.status_code)

    # Remove from whitelist — Nexus will cache the tarball from here
    whitelist.remove(REGISTRY, scope, package_name)

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
    "whitelisted first via the PATCH endpoint. After a successful download "
    "the package is removed from the whitelist.",
)
async def get_package_tarball(package_name: str, tarball_filename: str):
    return await _proxy_tarball(None, package_name, tarball_filename)


@router.get(
    "/@{scope}/{package_name}/-/{tarball_filename}",
    summary="Download scoped package tarball",
    description="Stream a tarball for a scoped npm package. The package must be "
    "whitelisted first via the PATCH endpoint.",
)
async def get_scoped_package_tarball(
    scope: str, package_name: str, tarball_filename: str
):
    return await _proxy_tarball(scope, package_name, tarball_filename)


# ---------------------------------------------------------------------------
# Whitelist management
# ---------------------------------------------------------------------------


@router.patch(
    "/{package_name}",
    summary="Whitelist an unscoped package",
    description="Add an unscoped npm package to the download whitelist. "
    "The package can then be downloaded once through the proxy.",
)
async def whitelist_package(package_name: str):
    whitelist.add(REGISTRY, None, package_name)
    return {"whitelisted": package_name}


@router.patch(
    "/@{scope}/{package_name}",
    summary="Whitelist a scoped package",
    description="Add a scoped npm package (e.g. ``@scope/name``) to the download whitelist.",
)
async def whitelist_scoped_package(scope: str, package_name: str):
    whitelist.add(REGISTRY, scope, package_name)
    return {"whitelisted": f"@{scope}/{package_name}"}

from collections import defaultdict
from contextlib import asynccontextmanager
import json

import httpx
from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import StreamingResponse

from ..auth import require_bearer_token

NPMJS_REGISTRY = "https://registry.npmjs.org"
TIMEOUT = httpx.Timeout(connect=5, read=30, write=10, pool=5)

router = APIRouter(
    prefix="/npm",
    tags=["npm"],
    dependencies=[Depends(require_bearer_token)],
)

# Shared client — initialize via lifespan or startup event
_client: httpx.AsyncClient | None = None

whitelisted_packages: dict[str, set[str]] = defaultdict(set)


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            base_url=NPMJS_REGISTRY,
            timeout=TIMEOUT,
            follow_redirects=True,
        )
    return _client


@asynccontextmanager
async def lifespan(_app):
    """Attach to your FastAPI app: FastAPI(lifespan=lifespan)"""
    yield
    if _client and not _client.is_closed:
        await _client.aclose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _registry_path(scope: str | None, package_name: str) -> str:
    return f"/@{scope}/{package_name}" if scope else f"/{package_name}"


def _rewrite_tarball_urls(metadata: dict, proxy_base_url: str) -> dict:
    """Replace registry.npmjs.org tarball URLs with our proxy URL."""
    raw = json.dumps(metadata)
    raw = raw.replace(NPMJS_REGISTRY, proxy_base_url)
    return json.loads(raw)


def _is_whitelisted(scope: str | None, package_name: str) -> bool:
    key = scope if scope else "_"
    return package_name in whitelisted_packages[key]


def _whitelist(scope: str | None, package_name: str) -> None:
    key = scope if scope else "_"
    whitelisted_packages[key].add(package_name)


# ---------------------------------------------------------------------------
# Metadata endpoints
# ---------------------------------------------------------------------------


async def _proxy_metadata(request: Request, scope: str | None, package_name: str):
    client = get_client()
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


@router.get("/{package_name}")
async def get_package_metadata(package_name: str, request: Request):
    return await _proxy_metadata(request, scope=None, package_name=package_name)


@router.get("/@{scope}/{package_name}")
async def get_scoped_package_metadata(scope: str, package_name: str, request: Request):
    return await _proxy_metadata(request, scope=scope, package_name=package_name)


# ---------------------------------------------------------------------------
# Tarball endpoints (streamed)
# ---------------------------------------------------------------------------


async def _proxy_tarball(scope: str | None, package_name: str, tarball_filename: str):
    if not _is_whitelisted(scope, package_name):
        return Response(content="Forbidden", status_code=403)

    client = get_client()
    path = _registry_path(scope, package_name)
    url = f"{path}/-/{tarball_filename}"

    upstream = await client.send(client.build_request("GET", url), stream=True)

    if upstream.status_code != 200:
        body = await upstream.aread()
        await upstream.aclose()
        return Response(content=body, status_code=upstream.status_code)

    # Remove from whitelist — Nexus will cache the tarball from here
    key = scope if scope else "_"
    whitelisted_packages[key].discard(package_name)

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


@router.get("/{package_name}/-/{tarball_filename}")
async def get_package_tarball(package_name: str, tarball_filename: str):
    return await _proxy_tarball(None, package_name, tarball_filename)


@router.get("/@{scope}/{package_name}/-/{tarball_filename}")
async def get_scoped_package_tarball(
    scope: str, package_name: str, tarball_filename: str
):
    return await _proxy_tarball(scope, package_name, tarball_filename)


# ---------------------------------------------------------------------------
# Whitelist management
# ---------------------------------------------------------------------------


@router.patch("/{package_name}")
async def whitelist_package(package_name: str):
    _whitelist(None, package_name)
    return {"whitelisted": package_name}


@router.patch("/@{scope}/{package_name}")
async def whitelist_scoped_package(scope: str, package_name: str):
    _whitelist(scope, package_name)
    return {"whitelisted": f"@{scope}/{package_name}"}

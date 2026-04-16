"""Maven Central proxy router.

Proxies artifacts from https://repo1.maven.org/maven2.  All requests are
transparently forwarded to the upstream repository.

Path layout
-----------
Maven Central uses a path-based scheme::

    /{groupId with dots→slashes}/{artifactId}/{version}/{filename}

For example::

    /org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar

Metadata lives at::

    /{groupId path}/{artifactId}/maven-metadata.xml

Environment variables
---------------------
MAVEN_UPSTREAM_URL : str
    Base URL of the upstream Maven repository
    (default: ``https://repo1.maven.org/maven2``).
"""

import logging
import os

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import JSONResponse, StreamingResponse

from .. import scanner
from ..auth import require_bearer_token
from ..http_client import get_client
from ..scanner import ScanResult, ScanStatus

logger = logging.getLogger(__name__)

REGISTRY = "maven"
UPSTREAM_URL = os.environ.get(
    "MAVEN_UPSTREAM_URL", "https://repo1.maven.org/maven2"
).rstrip("/")

router = APIRouter(
    prefix="/maven",
    tags=["maven"],
    dependencies=[Depends(require_bearer_token)],
)

# In-memory cache of scan results, keyed by "groupId:artifactId@version"
_scan_cache: dict[str, ScanResult] = {}


def _extract_maven_coordinates(artifact_path: str) -> tuple[str, str, str]:
    """Extract Maven coordinates from an artifact path.

    Path layout: ``groupId/artifactId/version/filename``
    e.g. ``org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar``
    returns ``("org.apache.commons", "commons-lang3", "3.14.0")``.
    """
    parts = artifact_path.strip("/").split("/")
    if len(parts) < 4:
        return "", "", "unknown"
    # Last 3 segments are: artifactId / version / filename
    version = parts[-2]
    artifact_id = parts[-3]
    group_id = ".".join(parts[:-3])
    return group_id, artifact_id, version


# ---------------------------------------------------------------------------
# Metadata endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/metadata/{artifact_path:path}",
    summary="Get Maven metadata",
    description="Fetch ``maven-metadata.xml`` or POM files from the upstream Maven "
    "repository. This endpoint transparently proxies metadata requests.",
)
async def get_metadata(artifact_path: str):
    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.get(f"/{artifact_path}")

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "application/xml"),
    )


# ---------------------------------------------------------------------------
# Artifact download (streamed)
# ---------------------------------------------------------------------------


@router.get(
    "/artifact/{artifact_path:path}",
    summary="Download a Maven artifact",
    description="Stream a Maven artifact (JAR, POM, AAR, etc.) from the upstream "
    "repository. If a security scanner is active, the package is scanned on the fly.",
)
async def download_artifact(artifact_path: str):
    group_id, artifact_id, version = _extract_maven_coordinates(artifact_path)
    package_name = f"{group_id}:{artifact_id}" if group_id else artifact_path
    logger.info("[maven] Download requested: %s@%s", package_name, version)

    # Scan if a scanner is active
    active_scanner = scanner.get_active()
    if active_scanner is not None:
        key = f"{package_name}@{version}"
        result = _scan_cache.get(key)

        if result is not None:
            logger.info("[maven] [SCAN] Cache hit for %s — status=%s", key, result.status.value)
        else:
            logger.info("[maven] [SCAN] Scanning %s with '%s'...", key, scanner.get_active_name())
            result = await active_scanner.scan_package(package_name, version, "maven")
            _scan_cache[key] = result

        if result.status == ScanStatus.FAILED:
            logger.warning("[maven] [BLOCKED] Download of %s blocked — %s", key, result.summary)
            return JSONResponse(
                content={
                    "error": "Security scan failed — download blocked",
                    "detail": result.summary,
                    "vulnerabilities": [v.model_dump() for v in result.vulnerabilities],
                },
                status_code=403,
            )

        if result.status == ScanStatus.ERROR:
            logger.warning("[maven] [SCAN] Scanner error for %s — allowing download (fail-open): %s", key, result.summary)

    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.send(
        client.build_request("GET", f"/{artifact_path}"), stream=True
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

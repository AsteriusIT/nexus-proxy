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

import os

from fastapi import APIRouter, Depends, Request, Response
from starlette.responses import StreamingResponse

from ..auth import require_bearer_token
from ..http_client import get_client

REGISTRY = "maven"
UPSTREAM_URL = os.environ.get(
    "MAVEN_UPSTREAM_URL", "https://repo1.maven.org/maven2"
).rstrip("/")

router = APIRouter(
    prefix="/maven",
    tags=["maven"],
    dependencies=[Depends(require_bearer_token)],
)


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
    "repository.",
)
async def download_artifact(artifact_path: str):
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

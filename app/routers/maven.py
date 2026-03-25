"""Maven Central proxy router.

Proxies artifacts from https://repo1.maven.org/maven2.  All requests are
transparently forwarded; artifact (JAR/POM/AAR/...) downloads are gated by an
in-memory whitelist keyed on ``groupId:artifactId``.

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

from .. import whitelist
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
# Helpers
# ---------------------------------------------------------------------------


def _parse_gav(artifact_path: str) -> tuple[str, str, str | None, str | None]:
    """Parse a Maven path into (groupId, artifactId, version, filename).

    Parameters
    ----------
    artifact_path:
        The full path after ``/maven/``, e.g.
        ``org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar``.

    Returns
    -------
    tuple
        ``(groupId, artifactId, version | None, filename | None)``
    """
    parts = artifact_path.strip("/").split("/")
    if len(parts) < 2:
        return ("/".join(parts), "", None, None)

    # The last path segment that looks like a version (starts with digit) or is
    # a filename marks the split point.  In Maven Central:
    #   - metadata path: group/.../artifact/maven-metadata.xml  (no version dir)
    #   - artifact path: group/.../artifact/version/filename

    # Heuristic: walk backwards.  The filename is the last segment.
    # The version is the segment before the filename if it exists.
    # Everything before version/filename is groupId.../artifactId.
    # We treat everything before the last two segments as group + artifact.

    filename = parts[-1]

    # Metadata files sit directly under artifactId (no version directory)
    if filename in ("maven-metadata.xml", "maven-metadata.xml.sha1", "maven-metadata.xml.md5"):
        artifact_id = parts[-2]
        group_id = ".".join(parts[:-2])
        return (group_id, artifact_id, None, filename)

    if len(parts) >= 4:
        version = parts[-2]
        artifact_id = parts[-3]
        group_id = ".".join(parts[:-3])
        return (group_id, artifact_id, version, filename)

    # Fallback: best-effort
    artifact_id = parts[-2] if len(parts) >= 2 else parts[-1]
    group_id = ".".join(parts[:-2]) if len(parts) > 2 else ""
    return (group_id, artifact_id, None, filename)


def _whitelist_key(group_id: str, artifact_id: str) -> str:
    """Build the whitelist namespace from groupId."""
    return group_id or "_"


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
# Artifact download (streamed, whitelist-gated)
# ---------------------------------------------------------------------------


@router.get(
    "/artifact/{artifact_path:path}",
    summary="Download a Maven artifact",
    description="Stream a Maven artifact (JAR, POM, AAR, etc.) from the upstream "
    "repository. The artifact must be whitelisted by ``groupId:artifactId`` "
    "first. After a successful download the whitelist entry is consumed.",
)
async def download_artifact(artifact_path: str):
    group_id, artifact_id, version, filename = _parse_gav(artifact_path)

    if not artifact_id:
        return Response(content="Bad artifact path", status_code=400)

    ns = _whitelist_key(group_id, artifact_id)
    if not whitelist.is_whitelisted(REGISTRY, ns, artifact_id):
        return Response(content="Forbidden", status_code=403)

    client = get_client(UPSTREAM_URL, name=REGISTRY)
    upstream = await client.send(
        client.build_request("GET", f"/{artifact_path}"), stream=True
    )

    if upstream.status_code != 200:
        body = await upstream.aread()
        await upstream.aclose()
        return Response(content=body, status_code=upstream.status_code)

    whitelist.remove(REGISTRY, ns, artifact_id)

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
    "/{group_id}/{artifact_id}",
    summary="Whitelist a Maven artifact",
    description="Add a Maven artifact to the download whitelist by "
    "``groupId`` and ``artifactId``. Use dot-separated ``groupId`` "
    "(e.g. ``org.apache.commons``).",
)
async def whitelist_maven_artifact(group_id: str, artifact_id: str):
    ns = _whitelist_key(group_id, artifact_id)
    whitelist.add(REGISTRY, ns, artifact_id)
    return {"whitelisted": f"{group_id}:{artifact_id}"}

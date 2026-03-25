"""Checkmarx One SCA scanner implementation.

Uses the **Full Scan** approach (Approach 1) from the Checkmarx One API:

1. Authenticate via OAuth2 client credentials.
2. Ensure a dedicated project exists (created once, reused afterwards).
3. Generate a presigned upload URL.
4. Build a minimal ``package.json`` for the requested package, ZIP it, and
   upload to the presigned URL.
5. Create an SCA-only scan.
6. Poll until the scan completes.
7. Fetch results and translate into a :class:`~app.scanner.ScanResult`.

Environment variables
---------------------
CHECKMARX_BASE_URL : str
    Checkmarx One API base URL (default: ``https://eu-2.ast.checkmarx.net``).
CHECKMARX_IAM_URL : str
    IAM token endpoint base URL (default: ``https://eu-2.iam.checkmarx.net``).
CHECKMARX_TENANT : str
    Tenant (realm) name.
CHECKMARX_CLIENT_ID : str
    OAuth2 client ID.
CHECKMARX_CLIENT_SECRET : str
    OAuth2 client secret.
CHECKMARX_PROJECT_NAME : str
    Name of the Checkmarx project to use for scans
    (default: ``nexus-proxy-sca``).
CHECKMARX_SCAN_TIMEOUT : int
    Maximum seconds to wait for a scan to complete (default: ``300``).
CHECKMARX_SEVERITY_THRESHOLD : str
    Comma-separated severity levels that cause a scan to **fail**
    (default: ``CRITICAL,HIGH``).
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import time
import zipfile

import httpx

from .. import scanner
from ..scanner import ScanResult, ScanStatus, SecurityScanner, Vulnerability

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (all from environment)
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("CHECKMARX_BASE_URL", "https://eu-2.ast.checkmarx.net").rstrip("/")
IAM_URL = os.environ.get("CHECKMARX_IAM_URL", "https://eu-2.iam.checkmarx.net").rstrip("/")
TENANT = os.environ.get("CHECKMARX_TENANT", "")
CLIENT_ID = os.environ.get("CHECKMARX_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CHECKMARX_CLIENT_SECRET", "")
PROJECT_NAME = os.environ.get("CHECKMARX_PROJECT_NAME", "nexus-proxy-sca")
SCAN_TIMEOUT = int(os.environ.get("CHECKMARX_SCAN_TIMEOUT", "300"))
SEVERITY_THRESHOLD = {
    s.strip().upper()
    for s in os.environ.get("CHECKMARX_SEVERITY_THRESHOLD", "CRITICAL,HIGH").split(",")
    if s.strip()
}

POLL_INTERVAL = 5  # seconds between status polls
TIMEOUT = httpx.Timeout(connect=10, read=30, write=30, pool=10)


# ---------------------------------------------------------------------------
# Checkmarx One scanner
# ---------------------------------------------------------------------------


class CheckmarxScanner(SecurityScanner):
    """Checkmarx One SCA scanner using the Full Scan API."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._token_expires_at: float = 0
        self._project_id: str | None = None

    # -- HTTP client --------------------------------------------------------

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True)
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # -- Authentication -----------------------------------------------------

    async def _ensure_token(self) -> str:
        """Return a valid access token, refreshing if needed."""
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token

        url = (
            f"{IAM_URL}/auth/realms/{TENANT}/protocol/openid-connect/token"
        )
        client = self._get_client()
        resp = await client.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 3600)
        return self._token  # type: ignore[return-value]

    async def _auth_headers(self) -> dict[str, str]:
        token = await self._ensure_token()
        return {"Authorization": f"Bearer {token}"}

    # -- Project management -------------------------------------------------

    async def _ensure_project(self) -> str:
        """Return the project ID, creating the project if needed."""
        if self._project_id:
            return self._project_id

        client = self._get_client()
        headers = await self._auth_headers()

        # Try to find existing project by name
        resp = await client.get(
            f"{BASE_URL}/api/projects",
            params={"name": PROJECT_NAME},
            headers=headers,
        )
        resp.raise_for_status()
        projects = resp.json().get("projects", [])
        for p in projects:
            if p.get("name") == PROJECT_NAME:
                self._project_id = p["id"]
                return self._project_id

        # Create new project
        resp = await client.post(
            f"{BASE_URL}/api/projects",
            json={
                "name": PROJECT_NAME,
                "groups": [],
                "tags": {"source": "nexus-proxy"},
                "criticality": 3,
            },
            headers=headers,
        )
        resp.raise_for_status()
        self._project_id = resp.json()["id"]
        logger.info("Created Checkmarx project: %s (%s)", PROJECT_NAME, self._project_id)
        return self._project_id  # type: ignore[return-value]

    # -- Scan workflow ------------------------------------------------------

    @staticmethod
    def _build_package_json(package_name: str, version: str) -> bytes:
        """Build a minimal ``package.json`` with a single dependency."""
        manifest = {
            "name": "nexus-proxy-scan",
            "version": "1.0.0",
            "private": True,
            "description": f"Security scan for {package_name}",
            "dependencies": {
                package_name: version if version != "latest" else "*",
            },
        }
        return json.dumps(manifest, indent=2).encode()

    @staticmethod
    def _zip_manifest(package_json: bytes) -> bytes:
        """Wrap ``package.json`` in an in-memory ZIP archive."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("package.json", package_json)
        return buf.getvalue()

    async def _upload_zip(self, zip_bytes: bytes) -> str:
        """Upload a ZIP to Checkmarx and return the presigned URL."""
        client = self._get_client()
        headers = await self._auth_headers()

        # Get presigned upload URL
        resp = await client.post(f"{BASE_URL}/api/uploads", headers=headers)
        resp.raise_for_status()
        upload_url = resp.json()["url"]

        # Upload ZIP to presigned URL
        await client.put(
            upload_url,
            content=zip_bytes,
            headers={"Content-Type": "application/zip"},
        )

        return upload_url

    async def _create_scan(self, upload_url: str, project_id: str) -> str:
        """Create an SCA-only scan and return the scan ID."""
        client = self._get_client()
        headers = await self._auth_headers()

        resp = await client.post(
            f"{BASE_URL}/api/scans",
            json={
                "type": "upload",
                "handler": {"uploadUrl": upload_url},
                "project": {"id": project_id},
                "config": [{"type": "sca", "value": {}}],
                "tags": {"proxy-check": "true"},
            },
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()["id"]

    async def _poll_scan(self, scan_id: str) -> str:
        """Poll scan status until terminal state. Returns final status string."""
        client = self._get_client()
        deadline = time.time() + SCAN_TIMEOUT
        terminal = {"Completed", "Partial", "Failed", "Canceled"}

        while time.time() < deadline:
            headers = await self._auth_headers()
            resp = await client.get(
                f"{BASE_URL}/api/scans/{scan_id}", headers=headers
            )
            resp.raise_for_status()
            status = resp.json().get("status", "")
            if status in terminal:
                return status
            await asyncio.sleep(POLL_INTERVAL)

        return "Timeout"

    async def _get_results(self, scan_id: str) -> dict:
        """Fetch scan results."""
        client = self._get_client()
        headers = await self._auth_headers()
        resp = await client.get(
            f"{BASE_URL}/api/results",
            params={"scan-id": scan_id, "limit": 1000},
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()

    async def _get_results_summary(self, scan_id: str) -> dict:
        """Fetch aggregated results summary."""
        client = self._get_client()
        headers = await self._auth_headers()
        resp = await client.get(
            f"{BASE_URL}/api/results-summary",
            params={"scan-ids": scan_id},
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()

    # -- Public interface ---------------------------------------------------

    async def scan_npm_package(
        self,
        package_name: str,
        version: str = "latest",
    ) -> ScanResult:
        """Scan an npm package via Checkmarx One Full Scan."""
        if not TENANT or not CLIENT_ID or not CLIENT_SECRET:
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="checkmarx",
                summary="Checkmarx credentials not configured "
                "(CHECKMARX_TENANT, CHECKMARX_CLIENT_ID, CHECKMARX_CLIENT_SECRET)",
            )

        try:
            # Build artefacts
            pkg_json = self._build_package_json(package_name, version)
            zip_bytes = self._zip_manifest(pkg_json)

            # Upload
            project_id = await self._ensure_project()
            upload_url = await self._upload_zip(zip_bytes)

            # Scan
            scan_id = await self._create_scan(upload_url, project_id)
            logger.info(
                "Checkmarx scan %s started for %s@%s", scan_id, package_name, version
            )

            # Poll
            final_status = await self._poll_scan(scan_id)
            if final_status not in ("Completed", "Partial"):
                return ScanResult(
                    status=ScanStatus.ERROR,
                    scanner="checkmarx",
                    scan_id=scan_id,
                    summary=f"Scan ended with status: {final_status}",
                )

            # Results
            results = await self._get_results(scan_id)
            vulnerabilities = self._parse_vulnerabilities(results)

            # Determine pass/fail
            blocking = [
                v for v in vulnerabilities if v.severity in SEVERITY_THRESHOLD
            ]
            status = ScanStatus.FAILED if blocking else ScanStatus.PASSED

            summary_data = {}
            try:
                summary_data = await self._get_results_summary(scan_id)
            except Exception:
                pass  # summary is optional

            return ScanResult(
                status=status,
                scanner="checkmarx",
                scan_id=scan_id,
                summary=self._build_summary(vulnerabilities, blocking),
                vulnerabilities=vulnerabilities,
                details={
                    "checkmarx_status": final_status,
                    "results_summary": summary_data,
                    "project_id": project_id,
                    "severity_threshold": sorted(SEVERITY_THRESHOLD),
                },
            )

        except httpx.HTTPStatusError as exc:
            logger.exception("Checkmarx API error for %s", package_name)
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="checkmarx",
                summary=f"Checkmarx API error: {exc.response.status_code} — {exc.response.text[:200]}",
            )
        except Exception as exc:
            logger.exception("Checkmarx scan failed for %s", package_name)
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="checkmarx",
                summary=f"Scan error: {exc}",
            )

    # -- Result parsing -----------------------------------------------------

    @staticmethod
    def _parse_vulnerabilities(results: dict) -> list[Vulnerability]:
        """Extract vulnerabilities from Checkmarx results payload."""
        vulns: list[Vulnerability] = []
        for item in results.get("results", []):
            if item.get("type") != "sca":
                continue
            data = item.get("data", {})
            vuln_id = item.get("vulnerabilityDetails", {}).get("cveId", "") or item.get("id", "")
            vulns.append(
                Vulnerability(
                    id=vuln_id,
                    severity=item.get("severity", "UNKNOWN").upper(),
                    package_name=data.get("packageIdentifier", ""),
                    package_version=data.get("packageVersion", ""),
                    description=item.get("description", "")[:500],
                )
            )
        return vulns

    @staticmethod
    def _build_summary(all_vulns: list[Vulnerability], blocking: list[Vulnerability]) -> str:
        if not all_vulns:
            return "No vulnerabilities found."
        counts: dict[str, int] = {}
        for v in all_vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        parts = [f"{sev}: {n}" for sev, n in sorted(counts.items())]
        summary = f"Found {len(all_vulns)} vulnerabilities ({', '.join(parts)})."
        if blocking:
            summary += f" {len(blocking)} blocking (threshold: {', '.join(sorted(SEVERITY_THRESHOLD))})."
        return summary


# ---------------------------------------------------------------------------
# Auto-register
# ---------------------------------------------------------------------------

scanner.register("checkmarx", CheckmarxScanner())

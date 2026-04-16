"""Checkmarx Malicious Package Identification API (MPAPI) scanner.

Uses the `Checkmarx MPAPI <https://docs.checkmarx.com>`_ to check individual
packages for supply-chain threats (malicious packages, data leakage,
star-jacking, etc.).  No OAuth, no project management, no polling — just a
single HTTP POST per package.

How it works
------------
1. POST a JSON array ``[{"name": "<pkg>", "type": "npm", "version": "<ver>"}]``
   to ``https://api.dusti.co/v1/packages``.
2. The response contains a ``risks`` list per package — empty means no issues.
3. Each risk carries a ``score`` (0-10) that is mapped to a severity label.
4. Risks whose severity meets the threshold block the download.

Environment variables
---------------------
CHECKMARX_MPAPI_URL : str
    MPAPI endpoint URL (default: ``https://api.dusti.co/v1/packages``).
CHECKMARX_MPAPI_TOKEN : str
    API token obtained from Checkmarx support.
CHECKMARX_MPAPI_TIMEOUT : int
    HTTP request timeout in seconds (default: ``30``).
CHECKMARX_SEVERITY_THRESHOLD : str
    Comma-separated severity levels that cause a scan to **fail**
    (default: ``CRITICAL,HIGH``).
"""

from __future__ import annotations

import logging
import os
import time

import httpx

from .. import scanner
from ..scanner import ScanResult, ScanStatus, SecurityScanner, Vulnerability

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (all from environment)
# ---------------------------------------------------------------------------

MPAPI_URL = os.environ.get(
    "CHECKMARX_MPAPI_URL", "https://api.dusti.co/v1/packages"
).rstrip("/")
MPAPI_TOKEN = os.environ.get("CHECKMARX_MPAPI_TOKEN", "")
MPAPI_TIMEOUT = int(os.environ.get("CHECKMARX_MPAPI_TIMEOUT", "30"))
SEVERITY_THRESHOLD = {
    s.strip().upper()
    for s in os.environ.get("CHECKMARX_SEVERITY_THRESHOLD", "CRITICAL,HIGH").split(",")
    if s.strip()
}

TIMEOUT = httpx.Timeout(connect=10, read=MPAPI_TIMEOUT, write=10, pool=10)

# Score → severity mapping (CVSS-like ranges)
_SCORE_THRESHOLDS: list[tuple[float, str]] = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
]


def _score_to_severity(score: float) -> str:
    """Convert a risk score (0-10) to a severity label."""
    for threshold, label in _SCORE_THRESHOLDS:
        if score >= threshold:
            return label
    return "INFO"


# ---------------------------------------------------------------------------
# Checkmarx MPAPI scanner
# ---------------------------------------------------------------------------


class CheckmarxScanner(SecurityScanner):
    """Checkmarx Malicious Package Identification API scanner."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True)
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def scan_package(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
    ) -> ScanResult:
        """Scan a package via Checkmarx MPAPI."""
        if not MPAPI_TOKEN:
            logger.error("[checkmarx] ERROR — CHECKMARX_MPAPI_TOKEN not configured")
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="checkmarx",
                summary="Checkmarx MPAPI token not configured (CHECKMARX_MPAPI_TOKEN)",
            )

        try:
            payload = [{"name": package_name, "type": ecosystem, "version": version}]
            headers = {
                "Authorization": f"token {MPAPI_TOKEN}",
                "Content-Type": "text/plain",
            }

            logger.info("[checkmarx] Querying MPAPI for %s@%s", package_name, version)
            logger.debug("[checkmarx] Request payload: %s", payload)

            client = self._get_client()
            t0 = time.monotonic()
            resp = await client.post(MPAPI_URL, content=str(payload).replace("'", '"'), headers=headers)
            elapsed_ms = (time.monotonic() - t0) * 1000

            logger.info(
                "[checkmarx] Response: HTTP %d in %.0fms for %s@%s",
                resp.status_code, elapsed_ms, package_name, version,
            )

            if resp.status_code != 200:
                logger.error(
                    "[checkmarx] ERROR — API returned %d for %s@%s: %s",
                    resp.status_code, package_name, version, resp.text[:300],
                )
                return ScanResult(
                    status=ScanStatus.ERROR,
                    scanner="checkmarx",
                    summary=f"MPAPI returned HTTP {resp.status_code}: {resp.text[:200]}",
                )

            data = resp.json()
            if not data:
                logger.info("[checkmarx] PASSED — %s@%s — empty response", package_name, version)
                return ScanResult(
                    status=ScanStatus.PASSED,
                    scanner="checkmarx",
                    summary="No risks found.",
                )

            # The response is an array; find our package entry
            pkg_result = data[0] if len(data) == 1 else next(
                (p for p in data if p.get("name") == package_name), data[0]
            )

            risks = pkg_result.get("risks", [])
            ioc = pkg_result.get("ioc", [])

            if not risks:
                logger.info("[checkmarx] PASSED — %s@%s — no risks found", package_name, version)
                return ScanResult(
                    status=ScanStatus.PASSED,
                    scanner="checkmarx",
                    summary="No risks found.",
                    details={
                        "status": pkg_result.get("status"),
                        "ioc": ioc,
                    },
                )

            # Parse risks into vulnerabilities
            vulnerabilities = self._parse_risks(risks, package_name, version)
            blocking = [v for v in vulnerabilities if v.severity in SEVERITY_THRESHOLD]
            status = ScanStatus.FAILED if blocking else ScanStatus.PASSED

            # Log every risk
            for v in vulnerabilities:
                is_blocking = v.severity in SEVERITY_THRESHOLD
                level = logging.WARNING if is_blocking else logging.INFO
                logger.log(
                    level,
                    "[checkmarx]   %s %s %s — %s",
                    "[BLOCKING]" if is_blocking else "[ok]     ",
                    v.severity.ljust(8),
                    v.id,
                    v.description[:120],
                )

            if status == ScanStatus.PASSED:
                logger.info(
                    "[checkmarx] PASSED — %s@%s — %d risks, 0 blocking",
                    package_name, version, len(vulnerabilities),
                )
            else:
                logger.warning(
                    "[checkmarx] FAILED — %s@%s — %d blocking out of %d risks (threshold: %s)",
                    package_name, version, len(blocking), len(vulnerabilities),
                    ",".join(sorted(SEVERITY_THRESHOLD)),
                )

            return ScanResult(
                status=status,
                scanner="checkmarx",
                summary=self._build_summary(vulnerabilities, blocking),
                vulnerabilities=vulnerabilities,
                details={
                    "mpapi_status": pkg_result.get("status"),
                    "ioc": ioc,
                    "severity_threshold": sorted(SEVERITY_THRESHOLD),
                },
            )

        except httpx.TimeoutException:
            logger.error(
                "[checkmarx] TIMEOUT — request for %s@%s exceeded %ds",
                package_name, version, MPAPI_TIMEOUT,
            )
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="checkmarx",
                summary=f"MPAPI request timed out after {MPAPI_TIMEOUT}s",
            )
        except httpx.ConnectError as exc:
            logger.error(
                "[checkmarx] CONNECTION ERROR — cannot reach %s for %s@%s: %s",
                MPAPI_URL, package_name, version, exc,
            )
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="checkmarx",
                summary=f"Cannot reach MPAPI at {MPAPI_URL}: {exc}",
            )
        except Exception as exc:
            logger.exception("[checkmarx] ERROR — unexpected failure scanning %s@%s", package_name, version)
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="checkmarx",
                summary=f"Scan error: {exc}",
            )

    # -- Result parsing -----------------------------------------------------

    @staticmethod
    def _parse_risks(
        risks: list[dict], package_name: str, version: str,
    ) -> list[Vulnerability]:
        """Convert MPAPI risk entries to Vulnerability models."""
        vulns: list[Vulnerability] = []
        for risk in risks:
            score = float(risk.get("score", 0))
            severity = _score_to_severity(score)
            vulns.append(
                Vulnerability(
                    id=risk.get("id", ""),
                    severity=severity,
                    package_name=package_name,
                    package_version=version,
                    description=risk.get("description", risk.get("title", ""))[:500],
                )
            )
        return vulns

    @staticmethod
    def _build_summary(all_vulns: list[Vulnerability], blocking: list[Vulnerability]) -> str:
        if not all_vulns:
            return "No risks found."
        counts: dict[str, int] = {}
        for v in all_vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        parts = [f"{sev}: {n}" for sev, n in sorted(counts.items())]
        summary = f"Found {len(all_vulns)} risks ({', '.join(parts)})."
        if blocking:
            summary += f" {len(blocking)} blocking (threshold: {', '.join(sorted(SEVERITY_THRESHOLD))})."
        return summary


# ---------------------------------------------------------------------------
# Auto-register
# ---------------------------------------------------------------------------

_token_status = "configured" if MPAPI_TOKEN else "NOT configured"
logger.info(
    "[checkmarx] Initializing Checkmarx MPAPI scanner (url=%s, token=%s, timeout=%ds, threshold=%s)",
    MPAPI_URL, _token_status, MPAPI_TIMEOUT, ",".join(sorted(SEVERITY_THRESHOLD)),
)
scanner.register("checkmarx", CheckmarxScanner())

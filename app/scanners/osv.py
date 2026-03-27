"""OSV.dev security scanner implementation.

Uses the `OSV.dev REST API <https://osv.dev>`_ to check individual packages
for known vulnerabilities.  No binary, no temp files, no subprocess — just a
single HTTP POST per package.

How it works
------------
1. POST ``{"package": {"name": "<pkg>", "ecosystem": "npm"}, "version": "<ver>"}``
   to ``https://api.osv.dev/v1/query``.
2. The response contains a ``vulns`` list — empty means no known issues.
3. Each vulnerability carries severity information (CVSS via the
   ``severity`` field or ``database_specific`` metadata).
4. Vulnerabilities whose severity meets the threshold block the download.

Environment variables
---------------------
OSV_API_URL : str
    Base URL of the OSV API (default: ``https://api.osv.dev``).
    Override for self-hosted OSV instances.
OSV_TIMEOUT : int
    HTTP request timeout in seconds (default: ``30``).
OSV_SEVERITY_THRESHOLD : str
    Comma-separated severity levels that cause a scan to **fail**
    (default: ``CRITICAL,HIGH``).
"""

from __future__ import annotations

import logging
import os

import httpx

from .. import scanner
from ..scanner import ScanResult, ScanStatus, SecurityScanner, Vulnerability

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (all from environment)
# ---------------------------------------------------------------------------

OSV_API_URL = os.environ.get("OSV_API_URL", "https://api.osv.dev").rstrip("/")
OSV_TIMEOUT = int(os.environ.get("OSV_TIMEOUT", "30"))
SEVERITY_THRESHOLD = {
    s.strip().upper()
    for s in os.environ.get("OSV_SEVERITY_THRESHOLD", "CRITICAL,HIGH").split(",")
    if s.strip()
}

TIMEOUT = httpx.Timeout(connect=10, read=OSV_TIMEOUT, write=10, pool=10)

# CVSS v3 score → severity label mapping
_CVSS_THRESHOLDS: list[tuple[float, str]] = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
]


def _cvss_to_severity(score: float) -> str:
    """Convert a CVSS v3 score to a severity label."""
    for threshold, label in _CVSS_THRESHOLDS:
        if score >= threshold:
            return label
    return "INFO"


def _extract_severity(vuln: dict) -> str:
    """Extract a severity label from an OSV vulnerability entry.

    OSV provides severity in multiple places:
    1. ``severity`` list with CVSS vectors — we parse the score.
    2. ``database_specific.severity`` — a direct label (e.g. from GHSA).
    3. Fallback to ``UNKNOWN``.
    """
    # 1. Try CVSS from severity list
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        if score_str:
            try:
                return _cvss_to_severity(float(score_str))
            except (ValueError, TypeError):
                pass
        # Try parsing score from CVSS vector string
        vector = sev.get("vector", "")
        if vector:
            # CVSS:3.x vectors don't embed score; some entries have "score" key
            pass

    # 2. Try database_specific severity (common in GHSA)
    db_specific = vuln.get("database_specific", {})
    if isinstance(db_specific, dict):
        sev_label = db_specific.get("severity", "")
        if isinstance(sev_label, str) and sev_label.upper() in {
            "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
        }:
            return sev_label.upper()
        # GHSA uses github_reviewed_at but also has severity
        ghsa_severity = db_specific.get("github_reviewed_at", "")

    # 3. Try ecosystem-specific fields
    for affected in vuln.get("affected", []):
        eco_sev = affected.get("database_specific", {})
        if isinstance(eco_sev, dict):
            source = eco_sev.get("source", "")
            sev_label = eco_sev.get("severity", "")
            if isinstance(sev_label, str) and sev_label.upper() in {
                "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
            }:
                return sev_label.upper()
            # Some ecosystems use cvss score directly
            cvss = eco_sev.get("cvss", {})
            if isinstance(cvss, dict):
                score = cvss.get("score") or cvss.get("baseScore")
                if score is not None:
                    try:
                        return _cvss_to_severity(float(score))
                    except (ValueError, TypeError):
                        pass

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# OSV scanner
# ---------------------------------------------------------------------------


class OsvScanner(SecurityScanner):
    """OSV.dev vulnerability scanner using the public REST API."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True)
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def scan_npm_package(
        self,
        package_name: str,
        version: str = "latest",
    ) -> ScanResult:
        """Query OSV.dev for vulnerabilities in an npm package."""
        if version in ("latest", "*", "unknown"):
            logger.warning(
                "[osv] Cannot scan %s — version is '%s', need an exact version",
                package_name, version,
            )
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="osv",
                summary=f"Cannot scan without an exact version (got '{version}')",
            )

        import time as _time

        try:
            query_url = f"{OSV_API_URL}/v1/query"
            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": "npm",
                },
                "version": version,
            }
            logger.info("[osv] Querying %s for %s@%s", query_url, package_name, version)
            logger.debug("[osv] Request payload: %s", payload)

            client = self._get_client()
            t0 = _time.monotonic()
            resp = await client.post(query_url, json=payload)
            elapsed_ms = (_time.monotonic() - t0) * 1000

            logger.info(
                "[osv] Response: HTTP %d in %.0fms for %s@%s",
                resp.status_code, elapsed_ms, package_name, version,
            )

            if resp.status_code != 200:
                logger.error(
                    "[osv] ERROR — API returned %d for %s@%s: %s",
                    resp.status_code, package_name, version, resp.text[:300],
                )
                return ScanResult(
                    status=ScanStatus.ERROR,
                    scanner="osv",
                    summary=f"OSV API returned HTTP {resp.status_code}: {resp.text[:200]}",
                )

            data = resp.json()
            osv_vulns = data.get("vulns", [])
            logger.info(
                "[osv] OSV returned %d vulnerabilities for %s@%s",
                len(osv_vulns), package_name, version,
            )

            if not osv_vulns:
                logger.info("[osv] PASSED — %s@%s — no known vulnerabilities", package_name, version)
                return ScanResult(
                    status=ScanStatus.PASSED,
                    scanner="osv",
                    summary="No vulnerabilities found.",
                )

            # Parse vulnerabilities
            vulnerabilities = self._parse_vulnerabilities(osv_vulns, package_name, version)
            blocking = [v for v in vulnerabilities if v.severity in SEVERITY_THRESHOLD]
            non_blocking = [v for v in vulnerabilities if v.severity not in SEVERITY_THRESHOLD]
            status = ScanStatus.FAILED if blocking else ScanStatus.PASSED

            # Log every vulnerability found
            for v in vulnerabilities:
                is_blocking = v.severity in SEVERITY_THRESHOLD
                level = logging.WARNING if is_blocking else logging.INFO
                logger.log(
                    level,
                    "[osv]   %s %s %s — %s",
                    "[BLOCKING]" if is_blocking else "[ok]     ",
                    v.severity.ljust(8),
                    v.id,
                    v.description[:120],
                )

            # Log summary
            if status == ScanStatus.PASSED:
                logger.info(
                    "[osv] PASSED — %s@%s — %d total, %d non-blocking, 0 blocking",
                    package_name, version, len(vulnerabilities), len(non_blocking),
                )
            else:
                logger.warning(
                    "[osv] FAILED — %s@%s — %d total, %d blocking (threshold: %s)",
                    package_name, version, len(vulnerabilities), len(blocking),
                    ",".join(sorted(SEVERITY_THRESHOLD)),
                )

            return ScanResult(
                status=status,
                scanner="osv",
                summary=self._build_summary(vulnerabilities, blocking),
                vulnerabilities=vulnerabilities,
                details={
                    "osv_response": data,
                    "severity_threshold": sorted(SEVERITY_THRESHOLD),
                },
            )

        except httpx.TimeoutException:
            logger.error(
                "[osv] TIMEOUT — request for %s@%s to %s exceeded %ds",
                package_name, version, OSV_API_URL, OSV_TIMEOUT,
            )
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="osv",
                summary=f"OSV API request timed out after {OSV_TIMEOUT}s",
            )
        except httpx.ConnectError as exc:
            logger.error(
                "[osv] CONNECTION ERROR — cannot reach %s for %s@%s: %s",
                OSV_API_URL, package_name, version, exc,
            )
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="osv",
                summary=f"Cannot reach OSV API at {OSV_API_URL}: {exc}",
            )
        except Exception as exc:
            logger.exception("[osv] ERROR — unexpected failure querying %s@%s", package_name, version)
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="osv",
                summary=f"Scan error: {exc}",
            )

    # -- Result parsing -----------------------------------------------------

    @staticmethod
    def _parse_vulnerabilities(
        osv_vulns: list[dict], package_name: str, version: str,
    ) -> list[Vulnerability]:
        """Convert OSV vulnerability entries to our Vulnerability model."""
        vulns: list[Vulnerability] = []
        for v in osv_vulns:
            vuln_id = v.get("id", "")
            aliases = v.get("aliases", [])
            # Prefer a CVE alias if available
            cve = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
            severity = _extract_severity(v)
            summary = v.get("summary", "") or v.get("details", "")

            logger.debug(
                "[osv] Parsed vuln: id=%s (osv_id=%s, aliases=%s), severity=%s",
                cve, vuln_id, aliases, severity,
            )

            vulns.append(
                Vulnerability(
                    id=cve,
                    severity=severity,
                    package_name=package_name,
                    package_version=version,
                    description=summary[:500],
                )
            )
        logger.debug("[osv] Parsed %d vulnerabilities from OSV response", len(vulns))
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

logger.info(
    "[osv] Initializing OSV.dev scanner (api=%s, timeout=%ds, threshold=%s)",
    OSV_API_URL, OSV_TIMEOUT, ",".join(sorted(SEVERITY_THRESHOLD)),
)
scanner.register("osv", OsvScanner())

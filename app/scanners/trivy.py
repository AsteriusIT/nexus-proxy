"""Trivy security scanner implementation.

Uses `trivy fs` to scan a minimal ``package.json`` for known vulnerabilities.

Two modes of operation:

- **Subprocess** (default): runs the ``trivy`` binary directly.  The binary
  must be available on ``$PATH`` or pointed to by ``TRIVY_BINARY``.
- **Client/server**: set ``TRIVY_SERVER_URL`` to delegate to a running
  ``trivy server`` instance (uses ``trivy client``).

Environment variables
---------------------
TRIVY_BINARY : str
    Path to the ``trivy`` binary (default: ``trivy``).
TRIVY_SERVER_URL : str
    URL of a running ``trivy server`` (e.g. ``http://trivy:4954``).
    When set, scans use ``--server`` mode.
TRIVY_TIMEOUT : int
    Maximum seconds for a single scan (default: ``300``).
TRIVY_SEVERITY_THRESHOLD : str
    Comma-separated severity levels that cause a scan to **fail**
    (default: ``CRITICAL,HIGH``).
TRIVY_EXTRA_ARGS : str
    Additional space-separated CLI arguments passed to every ``trivy`` call
    (e.g. ``--skip-db-update --offline-scan``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile

from .. import scanner
from ..scanner import ScanResult, ScanStatus, SecurityScanner, Vulnerability

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (all from environment)
# ---------------------------------------------------------------------------

TRIVY_BINARY = os.environ.get("TRIVY_BINARY", "trivy")
TRIVY_SERVER_URL = os.environ.get("TRIVY_SERVER_URL", "").strip() or None
TRIVY_TIMEOUT = int(os.environ.get("TRIVY_TIMEOUT", "300"))
SEVERITY_THRESHOLD = {
    s.strip().upper()
    for s in os.environ.get("TRIVY_SEVERITY_THRESHOLD", "CRITICAL,HIGH").split(",")
    if s.strip()
}
TRIVY_EXTRA_ARGS = os.environ.get("TRIVY_EXTRA_ARGS", "").strip()


# ---------------------------------------------------------------------------
# Trivy scanner
# ---------------------------------------------------------------------------


class TrivyScanner(SecurityScanner):
    """Trivy vulnerability scanner using ``trivy fs`` in subprocess mode."""

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _build_package_json(package_name: str, version: str) -> str:
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
        return json.dumps(manifest, indent=2)

    def _build_command(self, scan_dir: str) -> list[str]:
        """Build the ``trivy`` CLI command."""
        cmd = [
            TRIVY_BINARY,
            "fs",
            "--format", "json",
            "--scanners", "vuln",
            "--pkg-types", "library",
        ]
        if TRIVY_SERVER_URL:
            cmd.extend(["--server", TRIVY_SERVER_URL])
        if TRIVY_EXTRA_ARGS:
            cmd.extend(TRIVY_EXTRA_ARGS.split())
        cmd.append(scan_dir)
        return cmd

    # -- Public interface ---------------------------------------------------

    async def scan_npm_package(
        self,
        package_name: str,
        version: str = "latest",
    ) -> ScanResult:
        """Scan an npm package via ``trivy fs``."""
        try:
            with tempfile.TemporaryDirectory(prefix="trivy-scan-") as tmpdir:
                # Write package.json
                pkg_json = self._build_package_json(package_name, version)
                pkg_path = os.path.join(tmpdir, "package.json")
                with open(pkg_path, "w") as f:
                    f.write(pkg_json)
                logger.debug("[trivy] Created temp package.json for %s@%s in %s", package_name, version, tmpdir)

                cmd = self._build_command(tmpdir)
                mode = f"server={TRIVY_SERVER_URL}" if TRIVY_SERVER_URL else "local"
                logger.info("[trivy] Starting scan for %s@%s (mode=%s)", package_name, version, mode)
                logger.debug("[trivy] Command: %s", " ".join(cmd))

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=TRIVY_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.communicate()
                    logger.error(
                        "[trivy] TIMEOUT — scan for %s@%s exceeded %ds limit",
                        package_name, version, TRIVY_TIMEOUT,
                    )
                    return ScanResult(
                        status=ScanStatus.ERROR,
                        scanner="trivy",
                        summary=f"Trivy scan timed out after {TRIVY_TIMEOUT}s",
                    )

                stderr_text = stderr.decode(errors="replace").strip()
                if stderr_text:
                    logger.debug("[trivy] stderr: %s", stderr_text[:500])

                # Trivy exits 0 on success (even with vulns) when outputting JSON
                if proc.returncode != 0:
                    logger.error(
                        "[trivy] ERROR — process exited with code %d for %s@%s: %s",
                        proc.returncode, package_name, version, stderr_text[:300],
                    )
                    return ScanResult(
                        status=ScanStatus.ERROR,
                        scanner="trivy",
                        summary=f"Trivy exited with code {proc.returncode}: {stderr_text[:300]}",
                    )

                try:
                    report = json.loads(stdout)
                except json.JSONDecodeError:
                    logger.error(
                        "[trivy] ERROR — failed to parse JSON output for %s@%s: %s",
                        package_name, version, stdout.decode(errors="replace")[:200],
                    )
                    return ScanResult(
                        status=ScanStatus.ERROR,
                        scanner="trivy",
                        summary=f"Failed to parse Trivy JSON output: {stdout.decode(errors='replace')[:200]}",
                    )

                vulnerabilities = self._parse_vulnerabilities(report)
                blocking = [v for v in vulnerabilities if v.severity in SEVERITY_THRESHOLD]
                status = ScanStatus.FAILED if blocking else ScanStatus.PASSED

                if status == ScanStatus.PASSED:
                    logger.info(
                        "[trivy] PASSED — %s@%s — %d total vulnerabilities, 0 blocking",
                        package_name, version, len(vulnerabilities),
                    )
                else:
                    logger.warning(
                        "[trivy] FAILED — %s@%s — %d blocking out of %d total vulnerabilities",
                        package_name, version, len(blocking), len(vulnerabilities),
                    )
                    for v in blocking:
                        logger.warning(
                            "[trivy]   %s %s in %s@%s — %s",
                            v.severity, v.id, v.package_name, v.package_version, v.description[:120],
                        )

                return ScanResult(
                    status=status,
                    scanner="trivy",
                    summary=self._build_summary(vulnerabilities, blocking),
                    vulnerabilities=vulnerabilities,
                    details={
                        "trivy_report": report,
                        "severity_threshold": sorted(SEVERITY_THRESHOLD),
                    },
                )

        except FileNotFoundError:
            logger.error(
                "[trivy] ERROR — binary not found at '%s'. Install Trivy or set TRIVY_BINARY.",
                TRIVY_BINARY,
            )
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="trivy",
                summary=f"Trivy binary not found: {TRIVY_BINARY}. "
                "Install Trivy or set TRIVY_BINARY to the correct path.",
            )
        except Exception as exc:
            logger.exception("[trivy] ERROR — unexpected failure scanning %s@%s", package_name, version)
            return ScanResult(
                status=ScanStatus.ERROR,
                scanner="trivy",
                summary=f"Scan error: {exc}",
            )

    # -- Result parsing -----------------------------------------------------

    @staticmethod
    def _parse_vulnerabilities(report: dict) -> list[Vulnerability]:
        """Extract vulnerabilities from Trivy JSON report."""
        vulns: list[Vulnerability] = []
        for result in report.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                vulns.append(
                    Vulnerability(
                        id=v.get("VulnerabilityID", ""),
                        severity=v.get("Severity", "UNKNOWN").upper(),
                        package_name=v.get("PkgName", ""),
                        package_version=v.get("InstalledVersion", ""),
                        description=(v.get("Title", "") or v.get("Description", ""))[:500],
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

_mode = f"server={TRIVY_SERVER_URL}" if TRIVY_SERVER_URL else f"local binary={TRIVY_BINARY}"
logger.info("[trivy] Initializing Trivy scanner (mode=%s, timeout=%ds, threshold=%s)", _mode, TRIVY_TIMEOUT, ",".join(sorted(SEVERITY_THRESHOLD)))
scanner.register("trivy", TrivyScanner())

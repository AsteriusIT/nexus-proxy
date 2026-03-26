"""Security scanner abstraction layer.

Provides a pluggable interface for scanning packages before they are
downloaded.  Administrators can switch the active scanner at runtime via the
``/admin/scanner`` endpoints.

Architecture
------------
- :class:`ScanResult` — the outcome of a security scan.
- :class:`SecurityScanner` — abstract base class that every scanner provider
  must implement.
- :func:`register` / :func:`get_active` / :func:`set_active` — provider
  registry that allows hot-swapping the scanner without restart.

Adding a new scanner
--------------------
1. Subclass :class:`SecurityScanner`.
2. Call ``scanner.register("my-scanner", MyScanner())`` at import time.
3. Activate it via ``PUT /admin/scanner`` or the ``SECURITY_SCANNER`` env var.
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from enum import Enum

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ScanStatus(str, Enum):
    """Possible statuses for a security scan."""

    PASSED = "passed"
    """No blocking vulnerabilities found."""

    FAILED = "failed"
    """Blocking vulnerabilities detected — download should be denied."""

    PENDING = "pending"
    """Scan is still running."""

    ERROR = "error"
    """Scan could not be completed (infrastructure issue, timeout, …)."""


class Vulnerability(BaseModel):
    """A single vulnerability found during a scan."""

    id: str = Field(description="CVE or internal identifier")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    package_name: str = Field(default="", description="Affected package")
    package_version: str = Field(default="", description="Affected version")
    description: str = Field(default="", description="Short description")


class ScanResult(BaseModel):
    """The outcome of a security scan."""

    status: ScanStatus
    scanner: str = Field(description="Name of the scanner that produced this result")
    scan_id: str = Field(default="", description="Scanner-specific scan identifier")
    summary: str = Field(default="", description="Human-readable summary")
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    details: dict = Field(default_factory=dict, description="Scanner-specific raw data")


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class SecurityScanner(ABC):
    """Interface that every scanner provider must implement."""

    @abstractmethod
    async def scan_npm_package(
        self,
        package_name: str,
        version: str = "latest",
    ) -> ScanResult:
        """Scan an npm package and return the result.

        Implementations should create a minimal ``package.json``, send it to
        the scanning service, wait for the result, and translate it into a
        :class:`ScanResult`.
        """

    async def close(self) -> None:
        """Release resources held by this scanner (HTTP clients, etc.)."""


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

_scanners: dict[str, SecurityScanner] = {}
_active_name: str | None = os.environ.get("SECURITY_SCANNER", "").strip() or None

if _active_name:
    logger.info("[scanner] SECURITY_SCANNER env var set to: '%s'", _active_name)
else:
    logger.info("[scanner] No SECURITY_SCANNER env var — scanning disabled by default")


def register(name: str, instance: SecurityScanner) -> None:
    """Register a scanner provider under *name* (case-insensitive)."""
    _scanners[name.lower()] = instance
    logger.info("[scanner] Registered scanner provider: '%s' (%s)", name, type(instance).__name__)


def list_scanners() -> list[str]:
    """Return the names of all registered scanners."""
    return sorted(_scanners.keys())


def get_active() -> SecurityScanner | None:
    """Return the currently active scanner, or ``None`` if scanning is disabled."""
    if _active_name is None:
        return None
    return _scanners.get(_active_name.lower())


def get_active_name() -> str | None:
    """Return the name of the active scanner, or ``None``."""
    return _active_name


def set_active(name: str | None) -> None:
    """Set the active scanner by name.  Pass ``None`` to disable scanning."""
    global _active_name
    if name is not None:
        lower = name.lower()
        if lower not in _scanners:
            available = ", ".join(list_scanners()) or "(none)"
            logger.error("[scanner] Cannot activate unknown scanner '%s' — available: %s", name, available)
            raise ValueError(
                f"Unknown scanner '{name}'. Available: {available}"
            )
        _active_name = lower
        logger.info("[scanner] Security scanning ENABLED — active scanner: '%s'", _active_name)
    else:
        _active_name = None
        logger.info("[scanner] Security scanning DISABLED — no active scanner")


async def close_all() -> None:
    """Close all registered scanners."""
    for name, s in _scanners.items():
        logger.info("[scanner] Closing scanner: '%s'", name)
        await s.close()
    logger.info("[scanner] All scanners closed")

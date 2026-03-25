"""Admin router for managing the security scanner at runtime.

Provides endpoints to list registered scanners, view/change the active
scanner, and query scan results cached in memory.

All admin endpoints are protected by the same Bearer token auth as the
registry routers.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import scanner
from ..auth import require_bearer_token

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_bearer_token)],
)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ScannerInfo(BaseModel):
    """Current scanner configuration."""

    active: str | None = Field(description="Name of the active scanner, or null if disabled")
    available: list[str] = Field(description="All registered scanner names")


class SetScannerRequest(BaseModel):
    """Request body for changing the active scanner."""

    scanner: str | None = Field(
        description="Scanner name to activate, or null to disable scanning"
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/scanner",
    summary="Get current scanner configuration",
    description="Return the name of the active security scanner and the list of "
    "all registered scanner providers.",
    response_model=ScannerInfo,
)
async def get_scanner():
    return ScannerInfo(
        active=scanner.get_active_name(),
        available=scanner.list_scanners(),
    )


@router.put(
    "/scanner",
    summary="Set the active security scanner",
    description="Change the active security scanner at runtime.  Pass "
    "``{\"scanner\": \"checkmarx\"}`` to activate, or "
    "``{\"scanner\": null}`` to disable scanning entirely.",
    response_model=ScannerInfo,
)
async def set_scanner(body: SetScannerRequest):
    try:
        scanner.set_active(body.scanner)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ScannerInfo(
        active=scanner.get_active_name(),
        available=scanner.list_scanners(),
    )

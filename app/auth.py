"""Preemptive Bearer token auth to protect the proxy API (e.g. for Nexus)."""
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import get_proxy_bearer_token

_http_bearer = HTTPBearer(auto_error=False)


async def require_bearer_token(request: Request) -> None:
    """
    Dependency: when a proxy Bearer token is configured, require
    Authorization: Bearer <token> on the request; otherwise 401.
    If no token is configured, all requests are allowed.
    """
    required = get_proxy_bearer_token()
    if not required:
        return
    credentials: HTTPAuthorizationCredentials | None = await _http_bearer(request)
    if not credentials or credentials.credentials != required:
        raise HTTPException(status_code=401, detail="Invalid or missing Bearer token")

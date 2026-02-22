"""Configuration for the proxy (e.g. Bearer token for API protection)."""
import os
from pathlib import Path


def get_proxy_bearer_token() -> str | None:
    """
    Return the Bearer token required to call this proxy API.
    Read from env PROXY_BEARER_TOKEN, or from file path in PROXY_BEARER_TOKEN_FILE.
    Env takes precedence. If neither is set, returns None (no auth required).
    """
    token = os.environ.get("PROXY_BEARER_TOKEN", "").strip()
    if token:
        return token
    file_path = os.environ.get("PROXY_BEARER_TOKEN_FILE", "").strip()
    if not file_path:
        return None
    path = Path(file_path)
    if not path.is_file():
        return None
    return path.read_text().strip() or None

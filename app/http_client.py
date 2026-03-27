"""Shared HTTP client factory for upstream registry proxying.

Each registry gets its own ``httpx.AsyncClient`` with the appropriate base URL.
Clients are lazily created and reused for the lifetime of the application.
Call :func:`close_all` during shutdown to release connections.
"""

import httpx

TIMEOUT = httpx.Timeout(connect=5, read=30, write=10, pool=5)

_clients: dict[str, httpx.AsyncClient] = {}


def get_client(base_url: str, *, name: str | None = None) -> httpx.AsyncClient:
    """Return (or create) an async HTTP client for *base_url*.

    Parameters
    ----------
    base_url:
        The upstream registry URL (e.g. ``https://registry.npmjs.org``).
    name:
        Optional key used to store the client.  Defaults to *base_url*.
    """
    key = name or base_url
    client = _clients.get(key)
    if client is None or client.is_closed:
        client = httpx.AsyncClient(
            base_url=base_url,
            timeout=TIMEOUT,
            follow_redirects=True,
        )
        _clients[key] = client
    return client


async def close_all() -> None:
    """Close every open HTTP client.  Safe to call multiple times."""
    for client in _clients.values():
        if not client.is_closed:
            await client.aclose()
    _clients.clear()

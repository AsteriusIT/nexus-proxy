"""In-memory package whitelist shared across all registry routers.

Each registry type maintains its own namespace. Packages are removed from the
whitelist after a successful download (Nexus caches them, so repeated proxy
downloads are unnecessary). State is lost on restart.
"""

from collections import defaultdict

# Structure: { registry_type: { namespace: {package_names} } }
# - registry_type: "npm", "pypi", "maven", "nuget", "rubygems"
# - namespace: scope/group key (use "_" for packages without a namespace)
# - package_names: set of whitelisted package names
_store: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))


def is_whitelisted(registry: str, namespace: str | None, package: str) -> bool:
    """Check whether a package is currently whitelisted."""
    key = namespace or "_"
    return package in _store[registry][key]


def add(registry: str, namespace: str | None, package: str) -> None:
    """Add a package to the whitelist."""
    key = namespace or "_"
    _store[registry][key].add(package)


def remove(registry: str, namespace: str | None, package: str) -> None:
    """Remove a package from the whitelist (idempotent)."""
    key = namespace or "_"
    _store[registry][key].discard(package)

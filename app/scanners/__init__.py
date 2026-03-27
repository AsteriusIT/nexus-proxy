"""Security scanner implementations.

Import this package to auto-register all bundled scanners with the
:mod:`app.scanner` provider registry.
"""

from . import checkmarx  # noqa: F401 — triggers registration
from . import osv  # noqa: F401 — triggers registration

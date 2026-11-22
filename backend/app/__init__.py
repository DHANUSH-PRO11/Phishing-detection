"""
PhishShield Backend Application Package.
"""

from __future__ import annotations
import sys
import types
from pathlib import Path

# Add project root and backend dir to sys.path
_current_dir = Path(__file__).resolve().parent  # app
_backend_dir = _current_dir.parent  # backend
_repo_root = _backend_dir.parent  # repo root

for _p in (str(_repo_root), str(_backend_dir)):
    if _p not in sys.path and Path(_p).exists():
        sys.path.insert(0, _p)

# Ensure backend namespace package alias exists when imported as top-level 'app'
if "backend" not in sys.modules:
    try:
        import backend  # noqa: F401
    except ImportError:
        _backend_pkg = types.ModuleType("backend")
        _backend_pkg.__path__ = [str(_backend_dir)]
        sys.modules["backend"] = _backend_pkg
        sys.modules["backend.app"] = sys.modules[__name__]

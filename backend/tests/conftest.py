"""
Pytest configuration and test setup fixtures.

Ensures project root and backend directories are in sys.path so that
tests can be run seamlessly from either the repository root or the backend directory.
"""

import sys
from pathlib import Path

# Add project root and backend dir to sys.path
project_root = Path(__file__).resolve().parent.parent.parent
backend_dir = Path(__file__).resolve().parent.parent

for p in (str(project_root), str(backend_dir)):
    if p not in sys.path:
        sys.path.insert(0, p)

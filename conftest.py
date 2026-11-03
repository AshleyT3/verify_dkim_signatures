"""Make the single-module project importable from a checkout.

``pytest`` (the bare binary) puts the test file's directory on sys.path, not
the repository root, so ``import verify_dkim_signatures`` would fail even
though ``python -m pytest`` works. This keeps both invocations equally valid,
with or without ``pip install``.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

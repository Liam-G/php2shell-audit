#!/usr/bin/env python3
"""Source-tree launcher; installed users should run ``php2shell-audit``."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from php2shell_audit.cli import main  # noqa: E402, I001


if __name__ == "__main__":
    raise SystemExit(main())

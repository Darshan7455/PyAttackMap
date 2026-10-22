"""Module execution entry point for python -m pyattackmap."""

from __future__ import annotations

import sys
from pyattackmap.cli import main

if __name__ == "__main__":
    sys.exit(main())


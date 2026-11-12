#!/usr/bin/env python3
"""Command-line entry point for the Criterion benchmark regression gate.

The implementation lives in ``check_bench_regression.py`` so its tests can
import it as a module; this hyphenated path is the documented command.
"""

from __future__ import annotations

from check_bench_regression import main

if __name__ == "__main__":
    raise SystemExit(main())

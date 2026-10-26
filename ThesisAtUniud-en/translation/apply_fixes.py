#!/usr/bin/env python3
"""Apply verified reviewer fixes as exact, unique string replacements.

Usage: apply_fixes.py fixes.py   (fixes.py defines FIXES = [(rel_path, old, new), ...])
Every `old` must occur exactly once in its file, otherwise nothing is written.
"""
import runpy
import sys
from pathlib import Path

DST = Path(__file__).resolve().parents[1]
fixes = runpy.run_path(sys.argv[1])["FIXES"]
texts = {}
for rel, old, new in fixes:
    t = texts.setdefault(rel, (DST / rel).read_text())
    n = t.count(old)
    if n != 1:
        sys.exit(f"ABORT, nothing written: {rel}: {old!r} found {n} times")
    texts[rel] = t.replace(old, new)
for rel, t in texts.items():
    (DST / rel).write_text(t)
print(f"applied {len(fixes)} fixes to {len(texts)} files")

#!/usr/bin/env python3
"""Trims a Bazel disk cache to a size before it is saved: cache_gc.py <dir>
--max-gb N.

The least recently used entries go first. Bazel sets an entry's mtime when
it writes or hits it, and the Actions cache keeps mtimes, so the order holds
across runs. Bazel's own collector (--experimental_disk_cache_gc_max_size)
runs only after minutes of idleness, which a CI job never has. Files Bazel
left half-written (tmp/) go too.
"""

import argparse
import os
import pathlib
import shutil
import sys

GB = 1000 ** 3


def entries(root):
    out = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            p = pathlib.Path(dirpath, f)
            try:
                st = p.lstat()
            except FileNotFoundError:
                continue
            out.append((st.st_mtime, st.st_size, p))
    return out


def gc(root, max_bytes):
    """Deletes the oldest entries until the cache holds at most max_bytes;
    returns (bytes before, bytes after, entries deleted)."""
    root = pathlib.Path(root)
    shutil.rmtree(root / "tmp", ignore_errors=True)
    found = sorted(entries(root), key=lambda e: e[0])
    total = before = sum(size for _, size, _ in found)
    deleted = 0
    for _, size, path in found:
        if total <= max_bytes:
            break
        path.unlink(missing_ok=True)
        total -= size
        deleted += 1
    return before, total, deleted


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dir")
    ap.add_argument("--max-gb", type=float, required=True)
    a = ap.parse_args(argv)
    if not os.path.isdir(a.dir):
        print(f"cache_gc: no {a.dir}; nothing to trim")
        return 0
    before, after, deleted = gc(a.dir, int(a.max_gb * GB))
    print(f"cache_gc: {a.dir}: {before / GB:.2f} GB, {deleted} entries removed, {after / GB:.2f} GB left")
    return 0


if __name__ == "__main__":
    sys.exit(main())

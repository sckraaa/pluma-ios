#!/usr/bin/env python3
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import cache_gc  # noqa: E402


class GcTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        # ac/ and cas/ entries of 100 bytes, the oldest first.
        for i, rel in enumerate(("cas/aa/old", "ac/bb/older-hit", "cas/cc/new", "cas/dd/newest")):
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"x" * 100)
            os.utime(p, (1000 + i, 1000 + i))
        (self.root / "tmp").mkdir()
        (self.root / "tmp/partial").write_bytes(b"y" * 1000)

    def tearDown(self):
        self.dir.cleanup()

    def left(self):
        return sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file())

    def test_keeps_the_recently_used(self):
        self.assertEqual(cache_gc.gc(self.root, 250), (400, 200, 2))
        self.assertEqual(self.left(), ["cas/cc/new", "cas/dd/newest"])

    def test_within_the_limit(self):
        self.assertEqual(cache_gc.gc(self.root, 400), (400, 400, 0))
        self.assertEqual(len(self.left()), 4)

    def test_missing_dir(self):
        self.assertEqual(cache_gc.main([str(self.root / "none"), "--max-gb", "1"]), 0)


if __name__ == "__main__":
    unittest.main()

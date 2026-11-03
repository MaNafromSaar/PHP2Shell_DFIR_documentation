"""Tests for safe_extract.py with synthetic archives."""
import gzip
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import safe_extract as se  # noqa: E402


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SafeExtractTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.out = self.base / "out"
        self.addCleanup(self._tmp.cleanup)

    def make_tar(self, name="b.tar.gz") -> Path:
        path = self.base / name
        with tarfile.open(path, "w:gz") as tar:
            def add(member_name, data=b"x", mode=0o644, type_=tarfile.REGTYPE, linkname=""):
                info = tarfile.TarInfo(member_name)
                info.size = len(data) if type_ == tarfile.REGTYPE else 0
                info.mode = mode
                info.type = type_
                info.linkname = linkname
                tar.addfile(info, io.BytesIO(data) if type_ == tarfile.REGTYPE else None)
            add("web/index.php", b"<?php //ok", mode=0o4755)
            add("web/files/data.txt", b"hello")
            add("../escape.txt", b"bad")
            add("/abs/path.txt", b"bad")
            add("web/link-out", type_=tarfile.SYMTYPE, linkname="../../../etc/passwd")
            add("web/link-in", type_=tarfile.SYMTYPE, linkname="index.php")
            add("dev/null2", type_=tarfile.CHRTYPE)
        return path

    def test_hash_mismatch_aborts_before_extracting(self):
        archive = self.make_tar()
        dest = self.base / "work" / "copy"
        with self.assertRaises(se.ExtractError):
            se.extract(archive, "0" * 64, dest, self.out)
        self.assertFalse(dest.exists())

    def test_tar_unsafe_members_skipped_and_permissions_stripped(self):
        archive = self.make_tar()
        dest = self.base / "work" / "copy"
        summary, _ = se.extract(archive, sha(archive), dest, self.out)
        reasons = {s["name"]: s["reason"] for s in summary["skipped"]}
        self.assertIn("../escape.txt", reasons)
        self.assertIn("/abs/path.txt", reasons)
        self.assertIn("web/link-out", reasons)
        self.assertIn("dev/null2", reasons)
        self.assertFalse((self.base / "work" / "escape.txt").exists())
        self.assertFalse((self.base / "escape.txt").exists())
        mode = stat.S_IMODE((dest / "web/index.php").stat().st_mode)
        self.assertEqual(0o644, mode)
        self.assertEqual("hello", (dest / "web/files/data.txt").read_text())
        self.assertEqual(["web/link-in"], [s["path"] for s in summary["symlinks"]])

    def test_manifest_is_sha256sum_format(self):
        archive = self.make_tar()
        dest = self.base / "work" / "copy"
        summary, _ = se.extract(archive, sha(archive), dest, self.out)
        lines = Path(summary["manifest"]).read_text().splitlines()
        self.assertIn(hashlib.sha256(b"hello").hexdigest() + "  web/files/data.txt", lines)
        self.assertEqual(sorted(l.split("  ", 1)[1] for l in lines), [l.split("  ", 1)[1] for l in lines])
        report = json.loads((self.out / "copy.extract-report.json").read_text())
        self.assertEqual(sha(archive), report["archive_sha256"])

    def test_refuses_existing_destination(self):
        archive = self.make_tar()
        dest = self.base / "exists"
        dest.mkdir()
        with self.assertRaises(se.ExtractError):
            se.extract(archive, sha(archive), dest, self.out)

    def test_zip_traversal_and_symlink(self):
        path = self.base / "b.zip"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("ok/a.txt", "a")
            zf.writestr("../evil.txt", "bad")
            link = zipfile.ZipInfo("ok/link")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(link, "/etc/passwd")
        dest = self.base / "work" / "z"
        summary, _ = se.extract(path, sha(path), dest, self.out)
        self.assertEqual({"../evil.txt", "ok/link"}, {s["name"] for s in summary["skipped"]})
        self.assertTrue((dest / "ok/a.txt").exists())
        self.assertFalse((self.base / "evil.txt").exists())

    def test_gzip_single_file(self):
        path = self.base / "dump.sql.gz"
        with gzip.open(path, "wb") as handle:
            handle.write(b"INSERT INTO tl_user VALUES (1);")
        dest = self.base / "work" / "dump"
        summary, _ = se.extract(path, sha(path), dest, self.out)
        self.assertEqual("gzip", summary["archive_kind"])
        self.assertEqual(b"INSERT INTO tl_user VALUES (1);", (dest / "dump.sql").read_bytes())

    def test_plain_file_copied(self):
        path = self.base / "notes.txt"
        path.write_text("hi")
        dest = self.base / "work" / "notes"
        summary, _ = se.extract(path, sha(path), dest, self.out)
        self.assertEqual("plain", summary["archive_kind"])

    def test_size_limit(self):
        path = self.base / "big.tar"
        with tarfile.open(path, "w") as tar:
            info = tarfile.TarInfo("big.bin")
            info.size = 5000
            tar.addfile(info, io.BytesIO(b"a" * 5000))
        with self.assertRaises(se.ExtractError):
            se.extract(path, sha(path), self.base / "work" / "big", self.out, max_bytes=1000)

    def test_merge_parts_into_one_tree_without_overwriting(self):
        part1 = self.base / "uploads.zip"
        part2 = self.base / "uploads2.zip"
        with zipfile.ZipFile(part1, "w") as zf:
            zf.writestr("2026/10/a.jpg", "A")
            zf.writestr("shared.txt", "first")
        with zipfile.ZipFile(part2, "w") as zf:
            zf.writestr("2025/b.jpg", "B")
            zf.writestr("shared.txt", "second")
        dest = self.base / "work" / "wp-content" / "uploads"
        se.extract(part1, sha(part1), dest, self.out, merge=True, label="uploads")
        summary, _ = se.extract(part2, sha(part2), dest, self.out, merge=True, label="uploads2")
        self.assertEqual("first", (dest / "shared.txt").read_text())
        self.assertEqual("B", (dest / "2025/b.jpg").read_text())
        self.assertEqual(["shared.txt"], [s["name"] for s in summary["skipped"]])
        self.assertIn("not overwritten", summary["skipped"][0]["reason"])
        self.assertEqual(3, summary["files"])
        self.assertTrue((self.out / "uploads.manifest.sha256").exists())
        self.assertTrue((self.out / "uploads2.extract-report.json").exists())

    def test_merge_option_required_for_existing_destination(self):
        part = self.base / "p.zip"
        with zipfile.ZipFile(part, "w") as zf:
            zf.writestr("x.txt", "x")
        dest = self.base / "work" / "d"
        se.extract(part, sha(part), dest, self.out)
        with self.assertRaises(se.ExtractError):
            se.extract(part, sha(part), dest, self.out)

    def test_cli_merge_labels_by_archive_name(self):
        part = self.base / "backup-themes.zip"
        with zipfile.ZipFile(part, "w") as zf:
            zf.writestr("theme/style.css", "x")
        dest = self.base / "work" / "wp-content" / "themes"
        self.assertEqual(0, se.main([str(part), "--sha256", sha(part), "--dest", str(dest), "--merge", "--out", str(self.out)]))
        self.assertTrue((self.out / "backup-themes.manifest.sha256").exists())

    def test_cli_exit_codes(self):
        archive = self.make_tar()
        args = [str(archive), "--sha256", sha(archive), "--dest", str(self.base / "w1"), "--out", str(self.out)]
        self.assertEqual(3, se.main(args))  # unsafe entries skipped
        bad = [str(archive), "--sha256", "f" * 64, "--dest", str(self.base / "w2"), "--out", str(self.out)]
        self.assertEqual(2, se.main(bad))
        clean = self.base / "clean.tar"
        with tarfile.open(clean, "w") as tar:
            info = tarfile.TarInfo("a.txt")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"a"))
        self.assertEqual(0, se.main([str(clean), "--sha256", sha(clean), "--dest", str(self.base / "w3"),
                                     "--out", str(self.out)]))


if __name__ == "__main__":
    unittest.main()

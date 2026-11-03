"""Tests for evidence-log.sh against a temporary copy of a log and evidence files."""
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "evidence-log.sh"

LOG_TEMPLATE = """# Evidence Log

| ID | Date/time | Site | Description | Source | SHA-256 | Stored at | Collected by |
|----|-----------|------|-------------|--------|---------|-----------|--------------|
| E-001 | | | placeholder | | | | |
| E-002 | 2026-10-23 | a | existing | src | {existing_hash} | `data/existing.txt` | me |

## Handling rules

- keep it
"""


class EvidenceLogTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        (self.root / "data").mkdir()
        (self.root / "documentation").mkdir()
        existing = self.root / "data" / "existing.txt"
        existing.write_text("existing evidence\n")
        self.log = self.root / "documentation" / "evidence-log.md"
        self.log.write_text(LOG_TEMPLATE.format(existing_hash=hashlib.sha256(existing.read_bytes()).hexdigest()))
        self.env = {**os.environ, "EVIDENCE_LOG": str(self.log), "EVIDENCE_PROJECT_ROOT": str(self.root)}

    def run_script(self, *args):
        return subprocess.run([str(SCRIPT), *args], capture_output=True, text=True, env=self.env)

    def new_file(self, name, content):
        path = self.root / "data" / name
        path.write_text(content)
        return path

    def test_add_inserts_after_last_row_with_next_id(self):
        path = self.new_file("a.txt", "alpha\n")
        result = self.run_script("add", str(path), "--site", "site", "--desc", "A | B", "--source", "src",
                                 "--collector", "tester", "--time", "2026-10-24 12:00")
        self.assertEqual(0, result.returncode, result.stderr)
        lines = self.log.read_text().splitlines()
        row_index = next(i for i, l in enumerate(lines) if l.startswith("| E-003 "))
        self.assertTrue(lines[row_index - 1].startswith("| E-002 "))
        self.assertEqual("", lines[row_index + 1])
        self.assertIn("A \\| B", lines[row_index])
        self.assertIn(hashlib.sha256(b"alpha\n").hexdigest(), lines[row_index])
        self.assertIn("`data/a.txt`", lines[row_index])
        self.assertIn("## Handling rules", lines)

    def test_fill_placeholder_row(self):
        path = self.new_file("b.txt", "beta\n")
        result = self.run_script("add", str(path), "--id", "E-001", "--site", "s", "--desc", "filled", "--source", "x")
        self.assertEqual(0, result.returncode, result.stderr)
        text = self.log.read_text()
        self.assertEqual(1, text.count("| E-001 "))
        self.assertIn("filled", text)
        self.assertNotIn("| E-003 ", text)

    def test_refuses_overwrite_and_duplicate_hash(self):
        path = self.new_file("c.txt", "gamma\n")
        self.assertEqual(0, self.run_script("add", str(path), "--site", "s", "--desc", "d", "--source", "x").returncode)
        again = self.run_script("add", str(path), "--site", "s", "--desc", "d", "--source", "x")
        self.assertEqual(2, again.returncode)
        self.assertIn("already in the log", again.stderr)
        other = self.new_file("d.txt", "delta\n")
        overwrite = self.run_script("add", str(other), "--id", "E-002", "--site", "s", "--desc", "d", "--source", "x")
        self.assertEqual(2, overwrite.returncode)
        self.assertIn("refusing to overwrite", overwrite.stderr)

    def test_required_options_and_missing_file(self):
        path = self.new_file("e.txt", "epsilon\n")
        self.assertEqual(2, self.run_script("add", str(path), "--site", "s").returncode)
        self.assertEqual(2, self.run_script("add", str(self.root / "nope"), "--site", "s", "--desc", "d", "--source", "x").returncode)

    def test_verify_ok_mismatch_missing(self):
        ok = self.run_script("verify")
        self.assertEqual(0, ok.returncode, ok.stdout)
        self.assertIn("OK        E-002", ok.stdout)
        self.assertIn("SKIP      E-001", ok.stdout)
        (self.root / "data" / "existing.txt").write_text("tampered\n")
        bad = self.run_script("verify")
        self.assertEqual(1, bad.returncode)
        self.assertIn("MISMATCH  E-002", bad.stdout)
        (self.root / "data" / "existing.txt").unlink()
        gone = self.run_script("verify")
        self.assertEqual(1, gone.returncode)
        self.assertIn("MISSING   E-002", gone.stdout)

    def test_evidence_file_is_never_modified(self):
        path = self.new_file("f.txt", "zeta\n")
        before = (path.read_bytes(), path.stat().st_mtime_ns)
        self.run_script("add", str(path), "--site", "s", "--desc", "d", "--source", "x")
        self.assertEqual(before, (path.read_bytes(), path.stat().st_mtime_ns))

    def test_next_id(self):
        self.assertEqual("E-003", self.run_script("next-id").stdout.strip())


if __name__ == "__main__":
    unittest.main()

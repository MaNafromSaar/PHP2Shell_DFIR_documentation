"""The demo data generator produces data on which the tools find the planted indicators."""
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import apache_triage as at  # noqa: E402
import make_demo_data as demo  # noqa: E402
import webroot_scan as ws  # noqa: E402


class DemoDataTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        demo.main([str(self.out)])

    def test_scanner_finds_planted_files_only(self):
        findings, _ = ws.scan(self.out / "webroot", ws.DEFAULT_DATA_DIRS, None, None)
        flagged = {f.path for f in findings if f.severity != "info"}
        self.assertEqual({"files/uploads/cache.php", "files/gallery/photo.php.jpg", "files/.htaccess",
                          "templates/mod_banner.html5"}, flagged)

    def test_triage_finds_planted_events(self):
        entries, unparsed, bursts = at.analyse([self.out / "access.log"], None, None, "pentest-check", 60, 120)
        self.assertEqual(1, unparsed)
        self.assertEqual(["203.0.113.51"], [ip for ip, _, _ in bursts])
        tags = {t for e in entries for t in e.tags}
        self.assertTrue({"data-dir-code-access", "attack-pattern", "sensitive-200", "login-post", "scanner-ua",
                         "own-test", "burst"} <= tags)

    def test_deterministic_for_same_seed(self):
        other = self.out / "other"
        demo.main([str(other)])
        self.assertEqual((self.out / "access.log").read_text(), (other / "access.log").read_text())


if __name__ == "__main__":
    unittest.main()

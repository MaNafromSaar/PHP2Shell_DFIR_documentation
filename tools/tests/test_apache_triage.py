"""Tests for apache_triage.py using synthetic log lines."""
import csv
import gzip
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import apache_triage as at  # noqa: E402

UA = "Mozilla/5.0"


def line(ip="203.0.113.5", time="24/Oct/2026:11:00:00 +0200", req="GET / HTTP/1.1", status=200, size=100, ua=UA):
    return f'{ip} - - [{time}] "{req}" {status} {size} "-" "{ua}"'


class TriageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def log(self, lines, name="access.log") -> Path:
        path = self.dir / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def run_analysis(self, lines, **kwargs):
        params = dict(since=None, until=None, own_ua=None, burst_window=60, burst_threshold=120)
        params.update(kwargs)
        return at.analyse([self.log(lines)], **params)

    def tags_for(self, entries, path_part):
        return [e.tags for e in entries if path_part in e.path][0]

    def test_parse_and_unparsed_count(self):
        entries, unparsed, _ = self.run_analysis([line(), "garbage line", line(req="GET /a HTTP/1.1")])
        self.assertEqual(2, len(entries))
        self.assertEqual(1, unparsed)

    def test_code_in_data_dir_access(self):
        entries, _, _ = self.run_analysis([line(req="POST /files/up/x.php HTTP/1.1")])
        tags = entries[0].tags
        self.assertIn("data-dir-code-access", tags)
        self.assertIn("post-to-other-php", tags)
        self.assertEqual("high", at.worst_severity(tags))

    def test_sensitive_paths_and_200(self):
        entries, _, _ = self.run_analysis([
            line(req="GET /.env HTTP/1.1"),
            line(req="GET /contao/login HTTP/1.1"),
            line(req="GET /contao/main.php?do=page HTTP/1.1"),
            line(req="GET /_profiler/ HTTP/1.1", status=503),
        ])
        self.assertIn("sensitive-200", self.tags_for(entries, ".env"))
        self.assertEqual(["sensitive-path"], self.tags_for(entries, "/contao/login"))
        self.assertNotIn("sensitive-200", self.tags_for(entries, "main.php"))
        self.assertNotIn("sensitive-200", self.tags_for(entries, "_profiler"))

    def test_attack_patterns_including_double_encoding(self):
        entries, _, _ = self.run_analysis([
            line(req="GET /index.php?page=../../etc/passwd HTTP/1.1"),
            line(req="GET /index.php?f=%252e%252e%252fsecret HTTP/1.1"),
            line(req="GET /index.php?x=php://input HTTP/1.1"),
        ])
        self.assertTrue(all("attack-pattern" in e.tags for e in entries))

    def test_login_post_scanner_and_server_error(self):
        entries, _, _ = self.run_analysis([
            line(req="POST /contao/login HTTP/1.1"),
            line(req="GET /x HTTP/1.1", ua="sqlmap/1.7"),
            line(req="GET /boom HTTP/1.1", status=500),
        ])
        self.assertIn("login-post", entries[0].tags)
        self.assertIn("scanner-ua", entries[1].tags)
        self.assertIn("server-error", entries[2].tags)

    def test_post_to_index_php_is_not_flagged(self):
        entries, _, _ = self.run_analysis([line(req="POST /index.php HTTP/1.1")])
        self.assertEqual([], entries[0].tags)

    def test_own_test_traffic_is_excluded(self):
        entries, _, bursts = self.run_analysis(
            [line(req="GET /.env HTTP/1.1", ua="pentest-check (authorised)")] * 200, own_ua="pentest-check")
        self.assertEqual(["own-test"], entries[0].tags)
        self.assertEqual([], bursts)

    def test_burst_detection(self):
        lines = [line(ip="198.51.100.9", time=f"24/Oct/2026:11:00:{s % 60:02d} +0200") for s in range(130)]
        lines += [line(ip="198.51.100.10", time="24/Oct/2026:11:00:01 +0200")]
        entries, _, bursts = self.run_analysis(lines)
        self.assertEqual(1, len(bursts))
        self.assertEqual("198.51.100.9", bursts[0][0])
        self.assertTrue(all("burst" in e.tags for e in entries if e.ip == "198.51.100.9"))
        self.assertFalse(any("burst" in e.tags for e in entries if e.ip == "198.51.100.10"))

    def test_time_window_filter(self):
        lines = [line(time="23/Oct/2026:23:59:59 +0200"), line(time="24/Oct/2026:00:00:00 +0200"),
                 line(time="25/Oct/2026:00:00:00 +0200")]
        entries, _, _ = self.run_analysis(lines, since=datetime(2026, 10, 24), until=datetime(2026, 10, 25))
        self.assertEqual(1, len(entries))

    def test_gzip_logs_are_read(self):
        path = self.dir / "access.log.1.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write(line(req="GET /.env HTTP/1.1") + "\n")
        entries, _, _ = at.analyse([path], None, None, None, 60, 120)
        self.assertEqual(1, len(entries))

    def test_csv_and_markdown_with_anonymised_ips(self):
        entries, unparsed, bursts = self.run_analysis([line(ip="192.0.2.77", req="GET /.env HTTP/1.1"), line()])
        mask = lambda ip: at.pseudonym(ip, "salt")
        csv_path = self.dir / "t.csv"
        rows = at.write_csv(csv_path, entries, mask)
        self.assertEqual(1, rows)
        content = csv_path.read_text()
        self.assertNotIn("192.0.2.77", content)
        self.assertEqual(at.pseudonym("192.0.2.77", "salt"), list(csv.DictReader(content.splitlines()))[0]["ip"])
        report = at.render_markdown(entries, unparsed, bursts, mask, 5, [Path("access.log")])
        self.assertNotIn("192.0.2.77", report)
        self.assertIn("sensitive-200", report)

    def test_cli_runs(self):
        path = self.log([line(req="GET /.env HTTP/1.1")])
        out = self.dir / "r.md"
        self.assertEqual(0, at.main([str(path), "--markdown", str(out), "--csv", str(self.dir / "t.csv")]))
        self.assertIn("Apache log triage", out.read_text())

    def test_pseudonym_is_stable_and_salted(self):
        self.assertEqual(at.pseudonym("1.2.3.4", "a"), at.pseudonym("1.2.3.4", "a"))
        self.assertNotEqual(at.pseudonym("1.2.3.4", "a"), at.pseudonym("1.2.3.4", "b"))


if __name__ == "__main__":
    unittest.main()

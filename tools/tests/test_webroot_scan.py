"""Tests for webroot_scan.py using synthetic data only (nothing is executed)."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webroot_scan as ws  # noqa: E402


def write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class ScanTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "webroot"
        self.root.mkdir()
        self.addCleanup(self._tmp.cleanup)

    def rules(self, findings, path):
        return {f.rule for f in findings if f.path == path}

    def test_code_in_data_dir_and_decode_chain(self):
        write(self.root, "files/uploads/a.php", "<?php eval(base64_decode($_POST['x']));")
        findings, _ = ws.scan(self.root, ws.DEFAULT_DATA_DIRS, None, None)
        rules = self.rules(findings, "files/uploads/a.php")
        self.assertIn("code-in-data-dir", rules)
        self.assertIn("eval-decode-chain", rules)
        self.assertIn("exec-from-request", rules)

    def test_wordpress_uploads_are_data_dirs(self):
        write(self.root, "wp-content/uploads/2026/10/x.php", "<?php echo 1;")
        write(self.root, "wp-content/plugins/ok/ok.php", "<?php echo 1;")
        findings, _ = ws.scan(self.root, ws.DEFAULT_DATA_DIRS, None, None)
        self.assertEqual({"wp-content/uploads/2026/10/x.php"}, {f.path for f in findings if f.rule == "code-in-data-dir"})

    def test_double_extension_and_htaccess(self):
        write(self.root, "files/img.php.jpg", "GIF89a")
        write(self.root, "files/.htaccess", "AddType application/x-httpd-php .jpg")
        findings, _ = ws.scan(self.root, ws.DEFAULT_DATA_DIRS, None, None)
        self.assertIn("double-extension", self.rules(findings, "files/img.php.jpg"))
        self.assertIn("htaccess-in-data-dir", self.rules(findings, "files/.htaccess"))

    def test_legitimate_code_is_quiet(self):
        write(self.root, "src/Db.php", "<?php $pdo->exec('SELECT 1'); Foo::system('x'); $this->exec('y');")
        write(self.root, "templates/page.html5", "<?= $this->title ?>")
        write(self.root, "vendor/lib/Run.php", "<?php exec('ls');")
        findings, _ = ws.scan(self.root, ws.DEFAULT_DATA_DIRS, None, None)
        self.assertEqual([], findings)

    def test_exec_outside_libraries_is_info(self):
        write(self.root, "src/Run.php", "<?php exec('ls');")
        findings, _ = ws.scan(self.root, ws.DEFAULT_DATA_DIRS, None, None)
        self.assertEqual({"exec-function"}, self.rules(findings, "src/Run.php"))
        self.assertEqual("info", findings[0].severity)

    def test_server_variable_in_include_is_not_flagged(self):
        write(self.root, "src/Load.php", "<?php require_once $_SERVER['DOCUMENT_ROOT'] . '/x.php';")
        findings, _ = ws.scan(self.root, ws.DEFAULT_DATA_DIRS, None, None)
        self.assertEqual([], findings)

    def test_obfuscation_rules(self):
        blob = "A" * 320
        write(self.root, "src/o.php", f"<?php $a = '{blob}'; $b = '" + "\\x41" * 30 + "';")
        findings, _ = ws.scan(self.root, ws.DEFAULT_DATA_DIRS, None, None)
        self.assertEqual({"long-base64-blob", "hex-escape-run"}, self.rules(findings, "src/o.php"))

    def test_baseline_modified_and_added(self):
        original = write(self.root, "core/Core.php", "<?php // original")
        digest = hashlib.sha256(original.read_bytes()).hexdigest()
        baseline = Path(self._tmp.name) / "baseline.txt"
        baseline.write_text(f"{digest}  core/Core.php\n", encoding="utf-8")
        original.write_text("<?php // tampered", encoding="utf-8")
        write(self.root, "core/Extra.php", "<?php // new")
        findings, _ = ws.scan(self.root, ws.DEFAULT_DATA_DIRS, ws.load_baseline(baseline), None)
        self.assertIn("baseline-modified", self.rules(findings, "core/Core.php"))
        self.assertIn("baseline-added", self.rules(findings, "core/Extra.php"))

    def test_unchanged_baseline_file_is_quiet(self):
        original = write(self.root, "core/Core.php", "<?php // original")
        digest = hashlib.sha256(original.read_bytes()).hexdigest()
        baseline = Path(self._tmp.name) / "baseline.txt"
        baseline.write_text(f"{digest}  core/Core.php\n", encoding="utf-8")
        findings, _ = ws.scan(self.root, ws.DEFAULT_DATA_DIRS, ws.load_baseline(baseline), None)
        self.assertEqual([], findings)

    def test_symlinks_are_not_followed(self):
        outside = Path(self._tmp.name) / "outside"
        write(outside, "evil.php", "<?php eval(base64_decode($_POST['x']));")
        (self.root / "link").symlink_to(outside, target_is_directory=True)
        (self.root / "file_link.php").symlink_to(outside / "evil.php")
        findings, stats = ws.scan(self.root, ws.DEFAULT_DATA_DIRS, None, None)
        self.assertEqual([], findings)
        self.assertEqual(0, stats["files"])

    def test_scan_does_not_modify_files(self):
        path = write(self.root, "files/a.php", "<?php eval(base64_decode($_POST['x']));")
        before = (path.read_bytes(), path.stat().st_mtime_ns)
        ws.scan(self.root, ws.DEFAULT_DATA_DIRS, None, None)
        self.assertEqual(before, (path.read_bytes(), path.stat().st_mtime_ns))

    def test_cli_outputs_and_exit_codes(self):
        write(self.root, "files/a.php", "<?php eval(base64_decode($_POST['x']));")
        out_json = Path(self._tmp.name) / "out.json"
        out_md = Path(self._tmp.name) / "out.md"
        code = ws.main([str(self.root), "--json", str(out_json), "--markdown", str(out_md)])
        self.assertEqual(1, code)
        data = json.loads(out_json.read_text())
        self.assertTrue(any(f["rule"] == "code-in-data-dir" for f in data["findings"]))
        self.assertIn("review candidates", out_md.read_text())

    def test_clean_tree_exit_zero(self):
        write(self.root, "src/ok.php", "<?php echo 'hi';")
        self.assertEqual(0, ws.main([str(self.root), "--markdown", str(Path(self._tmp.name) / "r.md")]))

    def test_anonymise_hides_names_and_snippets(self):
        write(self.root, "files/secret-name.php", "<?php eval(base64_decode($_POST['x']));")
        findings, _ = ws.scan(self.root, ws.DEFAULT_DATA_DIRS, None, None)
        ws.anonymise_paths(findings)
        self.assertTrue(all("secret-name" not in f.path and f.snippet == "" for f in findings))
        self.assertTrue(all(f.path.startswith("files/file-") for f in findings))

    def test_load_baseline_parses_sha256sum_format(self):
        path = Path(self._tmp.name) / "b.txt"
        path.write_text(("a" * 64) + "  ./x/y.php\n" + ("b" * 64) + " *z.php\nnot a hash line\n", encoding="utf-8")
        self.assertEqual({"x/y.php": "a" * 64, "z.php": "b" * 64}, ws.load_baseline(path))


if __name__ == "__main__":
    unittest.main()

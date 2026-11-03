#!/usr/bin/env python3
"""Read-only scan of a copied web root for signs of tampering.

The scan never executes, modifies or follows links out of the target tree. It
reports review candidates, not verdicts: legitimate code also uses eval or
exec, so every finding needs a human decision.

Checks:
  1. Executable file types in data directories (uploads, caches, assets).
  2. Double extensions such as image.php.jpg.
  3. Suspicious code patterns (obfuscation, request data reaching an exec sink).
  4. Optional comparison with a known-good baseline (sha256sum format).
  5. Optional recently modified files (mtime is only a hint in a restored backup).

Standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

__version__ = "1.0.0"

CODE_EXTENSIONS = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".pht", ".phar", ".inc", ".shtml"}
# Contao 4.x: uploads, generated assets, temp and cache directories should not contain PHP.
DEFAULT_DATA_DIRS = ["files", "assets", "web/assets", "system/tmp", "system/cache", "var", "tmp", "upload", "uploads",
                     "wp-content/uploads", "wp-content/upgrade", "wp-content/cache", "wp-content/updraft"]
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
MAX_SCAN_BYTES = 5 * 1024 * 1024
SNIPPET_LEN = 100

SOURCE_VARS = r"\$_(?:GET|POST|REQUEST|COOKIE)"
SINKS = r"(?<![>:\w$])(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|include|include_once|require|require_once|create_function)"

# (rule id, severity, description, compiled regex)
PATTERNS = [
    ("exec-from-request", "high", "Request data passed to a code or command sink",
     re.compile(SINKS + r"\s*\(?\s*[^;\n]{0,80}" + SOURCE_VARS, re.I)),
    ("eval-decode-chain", "high", "eval/assert of decoded or decompressed data",
     re.compile(r"(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|hex2bin|convert_uudecode)\s*\(", re.I)),
    ("nested-decoders", "medium", "Several decoding functions chained",
     re.compile(r"(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(", re.I)),
    ("preg-replace-e", "high", "preg_replace with the /e modifier (code execution)",
     re.compile(r"preg_replace\s*\(\s*(['\"]).{1,60}?/[a-z]*e[a-z]*\1", re.I)),
    ("variable-function", "medium", "Function name taken from request data",
     re.compile(r"\$[a-z_]\w*\s*=\s*" + SOURCE_VARS + r"\s*\[[^\]]+\]\s*;[^\n]{0,80}\$[a-z_]\w*\s*\(", re.I)),
    ("backtick-exec", "medium", "Backtick operator with a variable",
     re.compile(r"`[^`\n]*\$[a-z_]\w*[^`\n]*`", re.I)),
    ("long-base64-blob", "medium", "Very long base64-like string literal",
     re.compile(r"['\"][A-Za-z0-9+/=]{300,}['\"]")),
    ("hex-escape-run", "medium", "Long run of hex escapes in a string",
     re.compile(r"(?:\\x[0-9a-fA-F]{2}){24,}")),
    ("chr-concat", "medium", "String built from many chr() calls",
     re.compile(r"(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){8,}", re.I)),
    ("known-shell-marker", "high", "Marker of a common web shell family",
     re.compile(r"\b(?:FilesMan|c99shell|r57shell|WSO\s*shell|b374k|China\s*Chopper|Weevely)\b", re.I)),
    ("exec-function", "info", "exec-family call (exec is not blocked by this host's disable_functions)",
     re.compile(r"(?<![>:\w$])(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(", re.I)),
    ("php-input", "info", "Reads raw request body",
     re.compile(r"php://input", re.I)),
]

# Paths where info-level noise from legitimate libraries is expected.
LIBRARY_PREFIXES = ("vendor/", "system/modules/", "node_modules/")


@dataclass
class Finding:
    path: str
    rule: str
    severity: str
    description: str
    sha256: str = ""
    size: int = 0
    mtime: str = ""
    lines: list[int] = field(default_factory=list)
    snippet: str = ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_snippet(text: str) -> str:
    text = re.sub(r"[^\x20-\x7e]", "?", text.strip())
    return text[:SNIPPET_LEN] + ("..." if len(text) > SNIPPET_LEN else "")


def load_baseline(path: Path) -> dict[str, str]:
    """Read `sha256sum` output: '<hash>  <relative path>' per line."""
    baseline: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", line.strip())
        if match:
            baseline[match.group(2).lstrip("./")] = match.group(1).lower()
    return baseline


def is_under(rel: str, prefixes: list[str]) -> bool:
    return any(rel == p or rel.startswith(p.rstrip("/") + "/") for p in prefixes)


def double_extension(name: str) -> bool:
    parts = name.lower().split(".")
    return len(parts) >= 3 and any("." + p in CODE_EXTENSIONS for p in parts[1:-1])


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if full.is_symlink() or not full.is_file():
                continue
            yield full, full.relative_to(root).as_posix()


def scan(root: Path, data_dirs: list[str], baseline: dict[str, str] | None,
         since_days: int | None) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    stats = {"files": 0, "code_files": 0, "unreadable": 0, "skipped_large": 0}
    baseline_dirs = {rel.rsplit("/", 1)[0] for rel in baseline} if baseline else set()
    cutoff = None
    if since_days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

    for full, rel in iter_files(root):
        stats["files"] += 1
        try:
            st = full.stat()
        except OSError:
            stats["unreadable"] += 1
            continue
        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
        ext = full.suffix.lower()
        is_code = ext in CODE_EXTENSIONS
        in_data_dir = is_under(rel, data_dirs)
        base = {"size": st.st_size, "mtime": mtime.isoformat(timespec="seconds")}

        def add(rule, severity, description, lines=None, snippet=""):
            try:
                digest = sha256_file(full)
            except OSError:
                digest = ""
            findings.append(Finding(rel, rule, severity, description, digest, lines=lines or [],
                                    snippet=snippet, **base))

        if is_code:
            stats["code_files"] += 1
        if is_code and in_data_dir:
            add("code-in-data-dir", "high", "Executable file type inside a data directory")
        if double_extension(full.name):
            add("double-extension", "high", "Executable extension hidden behind another extension")
        if full.name == ".htaccess" and in_data_dir:
            add("htaccess-in-data-dir", "medium", ".htaccess inside a data directory (can re-enable PHP)")

        if baseline is not None:
            known = baseline.get(rel)
            if known is not None:
                try:
                    if sha256_file(full) != known:
                        add("baseline-modified", "high", "File differs from the known-good baseline")
                except OSError:
                    stats["unreadable"] += 1
            elif is_code and rel.rsplit("/", 1)[0] in baseline_dirs:
                add("baseline-added", "medium", "PHP file not in the baseline, inside a directory the baseline covers")

        if is_code and cutoff and mtime >= cutoff:
            add("recently-modified", "low", f"Code file modified in the last {since_days} days (mtime may be unreliable)")

        if is_code or ext in {".html5", ".tpl", ".twig", ""}:
            if st.st_size > MAX_SCAN_BYTES:
                stats["skipped_large"] += 1
                continue
            try:
                text = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                stats["unreadable"] += 1
                continue
            for rule, severity, description, regex in PATTERNS:
                if severity == "info" and rel.startswith(LIBRARY_PREFIXES):
                    continue
                hits = [m for m in regex.finditer(text)]
                if not hits:
                    continue
                lines = sorted({text.count("\n", 0, m.start()) + 1 for m in hits})[:10]
                add(rule, severity, description, lines, safe_snippet(hits[0].group(0)))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.rule))
    return findings, stats


def anonymise_paths(findings: list[Finding]) -> None:
    """Keep directory structure but hide file names (for sanitised publication)."""
    for finding in findings:
        parts = finding.path.split("/")
        digest = hashlib.sha256(parts[-1].encode()).hexdigest()[:8]
        ext = Path(parts[-1]).suffix
        parts[-1] = f"file-{digest}{ext}"
        finding.path = "/".join(parts)
        finding.snippet = ""


def render_markdown(meta: dict, findings: list[Finding], stats: dict) -> str:
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}
    out = [
        "# Web root scan report", "",
        f"- Tool: webroot_scan.py {__version__}",
        f"- Started (UTC): {meta['started']}",
        f"- Target: `{meta['root']}`",
        f"- Baseline: {meta['baseline'] or 'none'}",
        f"- Files scanned: {stats['files']} (code files: {stats['code_files']}, unreadable: {stats['unreadable']}, "
        f"skipped as too large: {stats['skipped_large']})",
        f"- Findings: " + ", ".join(f"{n} {sev}" for sev, n in counts.items()), "",
        "Findings are review candidates, not verdicts. Confirm each one by reading the file in an isolated environment.", "",
        "| Severity | Rule | Path | Lines | SHA-256 | Snippet |",
        "|----------|------|------|-------|---------|---------|",
    ]
    for f in findings:
        snippet = f.snippet.replace("|", "\\|")
        lines = ",".join(map(str, f.lines))
        out.append(f"| {f.severity} | {f.rule} | `{f.path}` | {lines} | `{f.sha256[:16]}` | `{snippet}` |" if snippet
                   else f"| {f.severity} | {f.rule} | `{f.path}` | {lines} | `{f.sha256[:16]}` | |")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", type=Path, help="copy of the web root (never the live site)")
    parser.add_argument("--baseline", type=Path, help="known-good hashes in sha256sum format")
    parser.add_argument("--data-dir", action="append", help="directory (relative to root) that must not hold code; repeatable")
    parser.add_argument("--since-days", type=int, help="also list code files modified in the last N days")
    parser.add_argument("--json", type=Path, help="write findings as JSON")
    parser.add_argument("--markdown", type=Path, help="write a Markdown report")
    parser.add_argument("--anonymise", action="store_true", help="hide file names and snippets in the output")
    parser.add_argument("--fail-on", choices=["high", "medium", "low", "info"], default="high",
                        help="exit 1 if a finding of this severity or worse exists (default: high)")
    args = parser.parse_args(argv)

    if not args.root.is_dir():
        parser.error(f"not a directory: {args.root}")
    baseline = load_baseline(args.baseline) if args.baseline else None
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    findings, stats = scan(args.root, args.data_dir or DEFAULT_DATA_DIRS, baseline, args.since_days)
    if args.anonymise:
        anonymise_paths(findings)

    meta = {"started": started, "root": "<anonymised>" if args.anonymise else str(args.root),
            "baseline": str(args.baseline) if args.baseline and not args.anonymise else ("provided" if args.baseline else "")}
    if args.json:
        args.json.write_text(json.dumps({"tool": f"webroot_scan.py {__version__}", **meta, "stats": stats,
                                         "findings": [asdict(f) for f in findings]}, indent=2) + "\n", encoding="utf-8")
    report = render_markdown(meta, findings, stats)
    if args.markdown:
        args.markdown.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] <= threshold for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())

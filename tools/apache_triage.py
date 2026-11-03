#!/usr/bin/env python3
"""Triage of Apache access logs (combined format, plain or .gz).

Produces a summary, a tagged-event timeline (CSV) and a Markdown report. Tags
are hints for an analyst, not proof of an attack. Times are interpreted in the
log's own timezone. Standard library only.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import re
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

__version__ = "1.0.0"

LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

SENSITIVE_PATHS = re.compile(
    r"^/(?:contao(?:/|$)|_profiler|_wdt|app_dev\.php|\.env|\.git|composer\.(?:json|lock)|system/config|"
    r"wp-login\.php|xmlrpc\.php|phpmyadmin|vendor/phpunit|cgi-bin|server-status|install\.php|contao-manager)",
    re.I,
)
DATA_DIR_CODE = re.compile(r"^/(?:files|assets|web/assets|var|system/tmp|upload|uploads|tmp)/.*\.(?:php\d?|phtml|phar|pht)(?:$|/|\?)", re.I)
ATTACK_PATTERN = re.compile(
    r"(?:\.\./|%2e%2e|%00|<script|union\s+select|php://|data://|base64_decode|allow_url_include|auto_prepend_file|"
    r"\$\{jndi|/etc/passwd|\bcmd=|\bexec=|\bshell=|\beval\()",
    re.I,
)
SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|wpscan|zgrab|gobuster|dirbuster|nuclei|acunetix|havij|fuzz|feroxbuster", re.I)
INDEX_SCRIPTS = {"/index.php", "/app.php", "/app_dev.php", "/contao-manager.phar.php"}

TAG_SEVERITY = {
    "data-dir-code-access": "high",
    "attack-pattern": "high",
    "sensitive-200": "high",
    "post-to-other-php": "medium",
    "login-post": "medium",
    "scanner-ua": "medium",
    "sensitive-path": "low",
    "server-error": "low",
    "burst": "medium",
}
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3, "": 4}


@dataclass
class Entry:
    time: datetime
    ip: str
    method: str
    path: str
    status: int
    size: int
    ua: str
    source: str
    tags: list[str]


def open_log(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("rt", encoding="utf-8", errors="replace")


def parse_line(line: str, source: str) -> Entry | None:
    match = LINE_RE.match(line)
    if not match:
        return None
    try:
        when = datetime.strptime(match["time"], TIME_FORMAT)
    except ValueError:
        return None
    parts = match["req"].split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else match["req"]
    size = int(match["size"]) if match["size"].isdigit() else 0
    return Entry(when, match["ip"], method, path, int(match["status"]), size, match["ua"] or "", source, [])


def tag_entry(entry: Entry, own_ua: str | None) -> None:
    decoded = unquote(unquote(entry.path))
    route = decoded.split("?", 1)[0]
    if own_ua and own_ua in entry.ua:
        entry.tags.append("own-test")
        return
    if DATA_DIR_CODE.match(route):
        entry.tags.append("data-dir-code-access")
    if ATTACK_PATTERN.search(decoded) or ATTACK_PATTERN.search(entry.path):
        entry.tags.append("attack-pattern")
    if SENSITIVE_PATHS.match(route):
        entry.tags.append("sensitive-path")
        if entry.status == 200 and not route.lower().startswith("/contao"):
            entry.tags.append("sensitive-200")
    if entry.method == "POST":
        if re.match(r"^/contao/login/?$", route):
            entry.tags.append("login-post")
        elif re.search(r"\.php\d?$", route, re.I) and route.lower() not in INDEX_SCRIPTS:
            entry.tags.append("post-to-other-php")
    if SCANNER_UA.search(entry.ua):
        entry.tags.append("scanner-ua")
    if entry.status >= 500:
        entry.tags.append("server-error")


def find_bursts(entries: list[Entry], window: int, threshold: int) -> list[tuple[str, datetime, int]]:
    """Return (ip, start, count) for each IP whose requests inside `window` seconds reach `threshold`."""
    by_ip: dict[str, list[datetime]] = defaultdict(list)
    for entry in entries:
        if "own-test" not in entry.tags:
            by_ip[entry.ip].append(entry.time)
    bursts = []
    for ip, times in by_ip.items():
        times.sort()
        queue: deque[datetime] = deque()
        peak, peak_start = 0, times[0] if times else None
        for moment in times:
            queue.append(moment)
            while (moment - queue[0]).total_seconds() > window:
                queue.popleft()
            if len(queue) > peak:
                peak, peak_start = len(queue), queue[0]
        if peak >= threshold and peak_start is not None:
            bursts.append((ip, peak_start, peak))
    return sorted(bursts, key=lambda b: -b[2])


def pseudonym(value: str, salt: str) -> str:
    return "ip-" + hashlib.sha256((salt + value).encode()).hexdigest()[:8]


def worst_severity(tags: list[str]) -> str:
    severities = [TAG_SEVERITY.get(t, "") for t in tags]
    return min(severities, key=lambda s: SEVERITY_RANK[s]) if severities else ""


def parse_bound(text: str | None) -> datetime | None:
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise SystemExit(f"cannot parse time bound: {text} (use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)")


def analyse(paths: list[Path], since: datetime | None, until: datetime | None, own_ua: str | None,
            burst_window: int, burst_threshold: int):
    entries: list[Entry] = []
    unparsed = 0
    for path in paths:
        with open_log(path) as handle:
            for line in handle:
                if not line.strip():
                    continue
                entry = parse_line(line, path.name)
                if entry is None:
                    unparsed += 1
                    continue
                local = entry.time.replace(tzinfo=None)
                if (since and local < since) or (until and local >= until):
                    continue
                tag_entry(entry, own_ua)
                entries.append(entry)
    entries.sort(key=lambda e: e.time)
    bursts = find_bursts(entries, burst_window, burst_threshold)
    burst_ips = {ip for ip, _, _ in bursts}
    for entry in entries:
        if entry.ip in burst_ips and "own-test" not in entry.tags:
            entry.tags.append("burst")
    return entries, unparsed, bursts


def write_csv(path: Path, entries: list[Entry], mask) -> int:
    rows = 0
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["time", "ip", "method", "path", "status", "size", "user_agent", "source", "severity", "tags"])
        for e in entries:
            if not e.tags:
                continue
            writer.writerow([e.time.isoformat(), mask(e.ip), e.method, e.path, e.status, e.size, e.ua, e.source,
                             worst_severity(e.tags), ";".join(e.tags)])
            rows += 1
    return rows


def render_markdown(entries: list[Entry], unparsed: int, bursts, mask, top: int, files: list[Path]) -> str:
    out = ["# Apache log triage", "", f"- Tool: apache_triage.py {__version__}",
           f"- Files: {', '.join(p.name for p in files)}",
           f"- Requests parsed: {len(entries)} (unparsed lines: {unparsed})"]
    if entries:
        out.append(f"- Range: {entries[0].time.isoformat()} to {entries[-1].time.isoformat()}")
    status = Counter(f"{e.status // 100}xx" for e in entries)
    out += ["- Status classes: " + ", ".join(f"{k}: {v}" for k, v in sorted(status.items())), ""]

    tag_counts: Counter[str] = Counter()
    tag_ips: dict[str, set[str]] = defaultdict(set)
    for e in entries:
        for t in e.tags:
            tag_counts[t] += 1
            tag_ips[t].add(e.ip)
    out += ["## Tags", "", "| Tag | Severity | Requests | Distinct IPs |", "|-----|----------|----------|--------------|"]
    for tag, count in sorted(tag_counts.items(), key=lambda kv: (SEVERITY_RANK[TAG_SEVERITY.get(kv[0], '')], -kv[1])):
        out.append(f"| {tag} | {TAG_SEVERITY.get(tag, 'info')} | {count} | {len(tag_ips[tag])} |")

    out += ["", "## Bursts", ""]
    if bursts:
        out += ["| IP | Window start | Requests in window |", "|----|--------------|--------------------|"]
        out += [f"| {mask(ip)} | {start.isoformat()} | {count} |" for ip, start, count in bursts[:top]]
    else:
        out.append("None above the threshold.")

    out += ["", f"## Top {top} sources", "", "| IP | Requests |", "|----|----------|"]
    out += [f"| {mask(ip)} | {n} |" for ip, n in Counter(e.ip for e in entries).most_common(top)]
    out += ["", f"## Top {top} paths", "", "| Path | Requests |", "|------|----------|"]
    out += [f"| `{p.replace('|', '%7C')[:90]}` | {n} |"
            for p, n in Counter(e.path.split('?', 1)[0] for e in entries).most_common(top)]

    high = [e for e in entries if worst_severity(e.tags) == "high"]
    out += ["", "## High-severity events (first 25)", ""]
    if high:
        out += ["| Time | IP | Request | Status | Tags |", "|------|----|---------|--------|------|"]
        out += [f"| {e.time.isoformat()} | {mask(e.ip)} | `{e.method} {e.path.replace('|', '%7C')[:80]}` | {e.status} | {', '.join(e.tags)} |"
                for e in high[:25]]
    else:
        out.append("None.")
    out += ["", "Tags are hints. A 200 on a sensitive path or any request to PHP inside a data directory needs a manual look "
            "at the file and the surrounding requests from the same IP."]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("logs", nargs="+", type=Path, help="access log files (.gz allowed)")
    parser.add_argument("--since", help="start (log-local time), e.g. 2026-10-01")
    parser.add_argument("--until", help="end, exclusive, e.g. 2026-10-24")
    parser.add_argument("--own-ua", help="substring of your own test user agent; those requests are tagged own-test and excluded from analysis")
    parser.add_argument("--burst-window", type=int, default=60, help="seconds (default 60)")
    parser.add_argument("--burst-threshold", type=int, default=120, help="requests per window (default 120)")
    parser.add_argument("--csv", type=Path, help="write tagged events as CSV timeline")
    parser.add_argument("--markdown", type=Path, help="write the Markdown report (default: stdout)")
    parser.add_argument("--anonymise", action="store_true", help="replace IPs by pseudonyms")
    parser.add_argument("--salt", default="", help="salt for the pseudonyms (keep it private)")
    parser.add_argument("--top", type=int, default=10)
    args = parser.parse_args(argv)

    missing = [p for p in args.logs if not p.is_file()]
    if missing:
        parser.error("not a file: " + ", ".join(map(str, missing)))
    mask = (lambda ip: pseudonym(ip, args.salt)) if args.anonymise else (lambda ip: ip)

    entries, unparsed, bursts = analyse(args.logs, parse_bound(args.since), parse_bound(args.until), args.own_ua,
                                        args.burst_window, args.burst_threshold)
    if args.csv:
        write_csv(args.csv, entries, mask)
    report = render_markdown(entries, unparsed, bursts, mask, args.top, args.logs)
    if args.markdown:
        args.markdown.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

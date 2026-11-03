#!/usr/bin/env python3
"""Verify, then safely unpack an evidence archive into a working copy.

Meant for untrusted backups inside the analysis container. It:
  1. refuses to continue unless the archive matches the expected SHA-256;
  2. unpacks tar/zip/gz archives (or copies a plain file) into a NEW directory;
  3. skips unsafe members (absolute paths, '..', links or devices escaping the target) and reports them;
  4. strips all execute and special permission bits so nothing in the copy can be run by accident;
  5. writes a sha256sum-format manifest and a JSON report to the output directory.

Nothing from the archive is ever executed. Standard library only (Python 3.12+ for tar filters).
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

__version__ = "1.0.0"
MAX_REPORTED = 1000


class ExtractError(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unsafe_name(name: str) -> str | None:
    """Return the reason a member name is unsafe, or None."""
    normalized = name.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return "absolute path"
    if ".." in parts:
        return "parent directory component"
    if "\x00" in name:
        return "NUL byte in name"
    return None


class Report:
    def __init__(self) -> None:
        self.skipped: list[dict] = []
        self.symlinks: list[dict] = []
        self.files = 0
        self.bytes = 0

    def skip(self, name: str, reason: str) -> None:
        self.skipped.append({"name": name, "reason": reason})


def extract_tar(archive: Path, dest: Path, report: Report, max_bytes: int, max_files: int,
                no_overwrite: bool = False) -> None:
    def member_filter(member: tarfile.TarInfo, path: str):
        reason = unsafe_name(member.name)
        if reason:
            report.skip(member.name, reason)
            return None
        if no_overwrite and not member.isdir() and os.path.lexists(os.path.join(path, member.name)):
            report.skip(member.name, "already exists in the destination (not overwritten)")
            return None
        try:
            return tarfile.data_filter(member, path)
        except tarfile.FilterError as error:
            report.skip(member.name, type(error).__name__ + ": " + str(error))
            return None

    with tarfile.open(archive) as tar:
        total = count = 0
        members = []
        for member in tar:
            members.append(member)
            count += 1
            total += max(member.size, 0)
            if count > max_files:
                raise ExtractError(f"more than {max_files} entries")
            if total > max_bytes:
                raise ExtractError(f"uncompressed size exceeds {max_bytes} bytes")
        tar.extractall(dest, members=members, filter=member_filter)


def extract_zip(archive: Path, dest: Path, report: Report, max_bytes: int, max_files: int,
                no_overwrite: bool = False) -> None:
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > max_files:
            raise ExtractError(f"more than {max_files} entries")
        if sum(i.file_size for i in infos) > max_bytes:
            raise ExtractError(f"uncompressed size exceeds {max_bytes} bytes")
        for info in infos:
            reason = unsafe_name(info.filename)
            if reason:
                report.skip(info.filename, reason)
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                report.skip(info.filename, "symbolic link in zip (not created)")
                continue
            if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                report.skip(info.filename, "special file type")
                continue
            if no_overwrite and not info.is_dir() and os.path.lexists(dest / info.filename):
                report.skip(info.filename, "already exists in the destination (not overwritten)")
                continue
            zf.extract(info, dest)


def extract_gzip(archive: Path, dest: Path, max_bytes: int) -> None:
    target = dest / (archive.name[:-3] if archive.name.endswith(".gz") else archive.name + ".out")
    if os.path.lexists(target):
        raise ExtractError(f"file already exists in the destination: {target.name}")
    written = 0
    with gzip.open(archive, "rb") as source, target.open("wb") as out:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            written += len(chunk)
            if written > max_bytes:
                raise ExtractError(f"uncompressed size exceeds {max_bytes} bytes")
            out.write(chunk)


def strip_permissions(dest: Path, report: Report) -> None:
    for dirpath, dirnames, filenames in os.walk(dest, followlinks=False):
        os.chmod(dirpath, 0o755)
        for name in filenames:
            path = Path(dirpath) / name
            if path.is_symlink():
                report.symlinks.append({"path": path.relative_to(dest).as_posix(), "target": os.readlink(path)})
                continue
            os.chmod(path, 0o644)
        for name in dirnames:
            path = Path(dirpath) / name
            if path.is_symlink():
                report.symlinks.append({"path": path.relative_to(dest).as_posix(), "target": os.readlink(path)})


def write_manifest(dest: Path, manifest: Path, report: Report) -> None:
    entries = []
    for dirpath, dirnames, filenames in os.walk(dest, followlinks=False):
        for name in filenames:
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            report.files += 1
            report.bytes += path.stat().st_size
            entries.append((path.relative_to(dest).as_posix(), sha256_file(path)))
    lines = [f"{digest}  {rel}" for rel, digest in sorted(entries)]
    manifest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def extract(archive: Path, expected_sha256: str, dest: Path, out_dir: Path,
            max_bytes: int = 20 * 1024 ** 3, max_files: int = 2_000_000,
            merge: bool = False, label: str | None = None) -> tuple[dict, Report]:
    if not archive.is_file():
        raise ExtractError(f"not a file: {archive}")
    actual = sha256_file(archive)
    if actual != expected_sha256.strip().lower():
        raise ExtractError(f"SHA-256 mismatch: expected {expected_sha256}, got {actual}. Nothing was extracted.")
    if dest.exists() and not merge:
        raise ExtractError(f"destination already exists: {dest} (use --merge to add another part)")
    out_dir.mkdir(parents=True, exist_ok=True)
    dest.mkdir(parents=True, exist_ok=merge)
    label = label or dest.name

    report = Report()
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if tarfile.is_tarfile(archive):
        kind = "tar"
        extract_tar(archive, dest, report, max_bytes, max_files, no_overwrite=merge)
    elif zipfile.is_zipfile(archive):
        kind = "zip"
        extract_zip(archive, dest, report, max_bytes, max_files, no_overwrite=merge)
    elif archive.suffix == ".gz":
        kind = "gzip"
        extract_gzip(archive, dest, max_bytes)
    else:
        kind = "plain"
        if os.path.lexists(dest / archive.name):
            raise ExtractError(f"file already exists in the destination: {archive.name}")
        shutil.copyfile(archive, dest / archive.name)

    strip_permissions(dest, report)
    manifest = out_dir / f"{label}.manifest.sha256"
    write_manifest(dest, manifest, report)
    summary = {
        "tool": f"safe_extract.py {__version__}",
        "python": sys.version.split()[0],
        "started_utc": started,
        "archive": archive.name,
        "archive_sha256": actual,
        "archive_kind": kind,
        "destination": str(dest),
        "manifest": str(manifest),
        "files": report.files,
        "bytes": report.bytes,
        "skipped_count": len(report.skipped),
        "skipped": report.skipped[:MAX_REPORTED],
        "symlinks_count": len(report.symlinks),
        "symlinks": report.symlinks[:MAX_REPORTED],
    }
    (out_dir / f"{label}.extract-report.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--sha256", required=True, help="expected SHA-256 from the evidence log (mandatory)")
    parser.add_argument("--dest", type=Path, help="directory for the copy (default: /work/<archive name>); must be new unless --merge")
    parser.add_argument("--merge", action="store_true",
                        help="add this archive to an existing destination without overwriting files (for multi-part backups)")
    parser.add_argument("--label", help="name for the manifest and report files (default: destination name, or the archive name with --merge)")
    parser.add_argument("--out", type=Path, default=Path("/out"), help="directory for manifest and report")
    parser.add_argument("--max-gib", type=float, default=20, help="abort above this uncompressed size")
    parser.add_argument("--max-files", type=int, default=2_000_000)
    args = parser.parse_args(argv)

    stem = args.archive.name
    for suffix in (".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar", ".zip", ".gz"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    dest = args.dest or Path("/work") / stem
    label = args.label or (stem if args.merge else None)
    try:
        summary, _ = extract(args.archive, args.sha256, dest, args.out, int(args.max_gib * 1024 ** 3), args.max_files,
                             merge=args.merge, label=label)
    except (ExtractError, tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"extracted {summary['files']} files ({summary['archive_kind']}) to {summary['destination']}")
    print(f"manifest: {summary['manifest']}")
    if summary["skipped_count"]:
        print(f"WARNING: {summary['skipped_count']} unsafe entries skipped; see the report. "
              "Unsafe paths in a backup are themselves worth investigating.", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

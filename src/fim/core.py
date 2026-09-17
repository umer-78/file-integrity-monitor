"""Baselines and comparison.

A baseline records, for every file under a root: SHA-256, size, permission bits
and modification time. The baseline file itself is signed with HMAC-SHA256 when
a key is supplied, so an attacker who edits both a file and the baseline cannot
hide the change without the key.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

CHUNK = 1024 * 1024
FORMAT_VERSION = 1


@dataclass(frozen=True)
class FileRecord:
    sha256: str
    size: int
    mode: str  # e.g. "0o644"
    mtime: float


@dataclass
class Baseline:
    root: str
    created_at: str
    files: dict[str, FileRecord]

    def to_json(self) -> dict:
        return {
            "format": FORMAT_VERSION,
            "root": self.root,
            "created_at": self.created_at,
            "files": {k: asdict(v) for k, v in sorted(self.files.items())},
        }


@dataclass(frozen=True)
class Change:
    kind: str  # added | removed | modified | permissions
    path: str
    detail: str = ""


class BaselineError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def _excluded(rel: str, patterns: list[str]) -> bool:
    parts = rel.split("/")
    return any(
        fnmatch.fnmatch(rel, p) or any(fnmatch.fnmatch(part, p) for part in parts) for p in patterns
    )


def scan(root: Path, exclude: list[str] | None = None) -> dict[str, FileRecord]:
    root = root.resolve()
    patterns = list(exclude or [])
    records: dict[str, FileRecord] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        dirnames[:] = sorted(
            d for d in dirnames
            if not _excluded(d if rel_dir == "." else f"{rel_dir}/{d}", patterns)
        )
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if _excluded(rel, patterns):
                continue
            try:
                st = full.lstat()
                if stat.S_ISLNK(st.st_mode):
                    digest = hashlib.sha256(os.readlink(full).encode()).hexdigest()
                elif stat.S_ISREG(st.st_mode):
                    digest = sha256_file(full)
                else:
                    continue  # sockets, fifos, devices
            except (PermissionError, FileNotFoundError):
                continue
            records[rel] = FileRecord(digest, st.st_size, oct(stat.S_IMODE(st.st_mode)), st.st_mtime)
    return records


def build_baseline(root: str | Path, exclude: list[str] | None = None) -> Baseline:
    root = Path(root)
    if not root.is_dir():
        raise BaselineError(f"not a directory: {root}")
    return Baseline(str(root.resolve()), datetime.now(timezone.utc).isoformat(), scan(root, exclude))


def _signature(payload: bytes, key: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def save_baseline(baseline: Baseline, path: str | Path, key: bytes | None = None) -> None:
    body = baseline.to_json()
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    doc = {"baseline": body, "hmac": _signature(payload, key) if key else None}
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2))
    os.replace(tmp, path)


def load_baseline(path: str | Path, key: bytes | None = None) -> Baseline:
    try:
        doc = json.loads(Path(path).read_text())
        body = doc["baseline"]
    except (OSError, ValueError, KeyError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    if body.get("format") != FORMAT_VERSION:
        raise BaselineError(f"unsupported baseline format {body.get('format')!r}")
    if key:
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        if not doc.get("hmac") or not hmac.compare_digest(doc["hmac"], _signature(payload, key)):
            raise BaselineError("baseline signature does not match: it was altered or the key is wrong")
    files = {k: FileRecord(**v) for k, v in body["files"].items()}
    return Baseline(body["root"], body["created_at"], files)


def compare(baseline: Baseline, current: dict[str, FileRecord]) -> list[Change]:
    changes: list[Change] = []
    old = baseline.files
    for path in sorted(old.keys() - current.keys()):
        changes.append(Change("removed", path))
    for path in sorted(current.keys() - old.keys()):
        changes.append(Change("added", path, f"{current[path].size} bytes"))
    for path in sorted(old.keys() & current.keys()):
        a, b = old[path], current[path]
        if a.sha256 != b.sha256:
            changes.append(Change("modified", path, f"size {a.size} → {b.size}"))
        elif a.mode != b.mode:
            changes.append(Change("permissions", path, f"{a.mode} → {b.mode}"))
    return changes

"""Hash-pinning (drift lock) for skill directories.

`skillguard lock` records a SHA-256 for every scannable file. `skillguard
verify` re-hashes and reports added / removed / changed files, so an
update to an installed skill cannot silently add a network call or a
credential read. The lockfile is plain JSON and is meant to be committed
next to the skill it pins.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import collect_files, file_sha256

LOCK_VERSION = 1


@dataclass
class Drift:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def to_dict(self) -> dict:
        return {"added": self.added, "removed": self.removed, "changed": self.changed}


def create_lock(root: Path) -> dict:
    root = root.resolve()
    entries: dict[str, str] = {}
    for path in collect_files(root):
        rel = str(path.relative_to(root))
        entries[rel] = file_sha256(path)
    return {"version": LOCK_VERSION, "root": root.name, "files": dict(sorted(entries.items()))}


def write_lock(root: Path, lock_path: Path) -> dict:
    data = create_lock(root)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data


def load_lock(lock_path: Path) -> dict:
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != LOCK_VERSION:
        raise ValueError(f"Unsupported lockfile format: {lock_path}")
    if not isinstance(data.get("files"), dict):
        raise ValueError(f"Lockfile has no file hashes: {lock_path}")
    return data


def verify_lock(root: Path, lock_path: Path) -> Drift:
    expected = load_lock(lock_path)["files"]
    current = create_lock(root)["files"]
    return Drift(
        added=sorted(set(current) - set(expected)),
        removed=sorted(set(expected) - set(current)),
        changed=sorted(k for k in set(current) & set(expected) if current[k] != expected[k]),
    )

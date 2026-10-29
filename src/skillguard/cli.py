"""SkillGuard CLI: scan, lock, and verify AI agent skills, offline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .lockfile import verify_lock, write_lock
from .scanner import scan_path

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _fail_on_severity(fail_on: str, counts: dict[str, int]) -> bool:
    if fail_on == "never":
        return False
    threshold = SEVERITY_ORDER[fail_on]
    return any(counts.get(sev, 0) and SEVERITY_ORDER[sev] <= threshold for sev in counts)


def _print_table(result) -> None:
    counts = result.counts
    print(f"Scanned {result.files_scanned} file(s) under {result.root}")
    print(f"Findings: {counts['high']} high, {counts['medium']} medium, {counts['low']} low")
    if not result.findings:
        print("No findings. This does not prove a skill is safe -- review it yourself before installing.")
        return
    for f in sorted(result.findings, key=lambda x: (SEVERITY_ORDER[x.severity], x.file, x.line)):
        print(f"\n[{f.severity.upper()}] {f.rule_id} {f.title}")
        print(f"  {f.file}:{f.line}: {f.snippet}")
        print(f"  Fix: {f.recommendation}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillguard",
        description="Offline scanner and drift lock for AI agent skills (SKILL.md, hooks, MCP configs). Never executes the files it scans.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a skill directory or file for risky patterns.")
    scan.add_argument("path", type=Path, help="Skill directory or file to scan")
    scan.add_argument("--format", choices=["table", "json"], default="table")
    scan.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                      help="Exit non-zero if a finding at or above this severity exists (default: high)")
    scan.add_argument("--allow", action="append", default=[], metavar="SG001",
                      help="Rule ID to suppress (repeatable). Prefer inline `# skillguard: ignore SG001` so suppressions stay visible in the file.")

    lock = sub.add_parser("lock", help="Record SHA-256 hashes of all scannable files.")
    lock.add_argument("path", type=Path, help="Skill directory to pin")
    lock.add_argument("--output", type=Path, default=None, help="Lockfile path (default: <path>/skillguard.lock.json)")

    verify = sub.add_parser("verify", help="Check a skill directory against a lockfile and report drift.")
    verify.add_argument("path", type=Path, help="Skill directory to check")
    verify.add_argument("--lock", type=Path, required=True, help="Lockfile created by `skillguard lock`")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "scan":
        if not args.path.exists():
            print(f"error: path does not exist: {args.path}", file=sys.stderr)
            return 2
        result = scan_path(args.path, allowlist=set(args.allow))
        if args.format == "json":
            print(json.dumps(result.to_dict(), indent=2))
        else:
            _print_table(result)
        return 1 if _fail_on_severity(args.fail_on, result.counts) else 0

    if args.command == "lock":
        if not args.path.is_dir():
            print("error: lock requires a directory", file=sys.stderr)
            return 2
        out = args.output or (args.path / "skillguard.lock.json")
        data = write_lock(args.path, out)
        print(f"Wrote {len(data['files'])} hash(es) to {out}")
        return 0

    if args.command == "verify":
        if not args.path.exists() or not args.lock.exists():
            print("error: path and lockfile must both exist", file=sys.stderr)
            return 2
        try:
            drift = verify_lock(args.path, args.lock)
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot verify lockfile: {exc}", file=sys.stderr)
            return 2
        if not drift.has_drift:
            print("No drift: all files match the lockfile.")
            return 0
        print("Drift detected -- review the changed files before using this skill:")
        for label, items in (("added", drift.added), ("removed", drift.removed), ("changed", drift.changed)):
            for item in items:
                print(f"  {label}: {item}")
        return 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

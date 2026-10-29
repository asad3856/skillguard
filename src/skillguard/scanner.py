"""SkillGuard: offline scanner and drift lock for AI agent skills.

A skill (SKILL.md, commands, hooks, MCP config) is installable code that a
coding agent will execute. SkillGuard reads those files as *text only* --
it never executes them -- and flags patterns that commonly indicate
prompt injection, credential access, or data exfiltration.

Standard library only. No network access. Safe to run on untrusted input.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILE_BYTES = 1_000_000
SKILL_FILENAMES = {"SKILL.md", "skill.md"}
# Extensions / names worth scanning inside a skill directory.
SCAN_SUFFIXES = {".md", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".sh", ".py", ".js", ".ts"}
SCAN_NAMES = {"SKILL.md", ".claude-plugin", "plugin.json", "mcp.json", ".mcp.json"}
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", ".mypy_cache", ".ruff_cache"}
LOCKFILE_NAME = "skillguard.lock.json"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str  # high | medium | low
    pattern: re.Pattern[str]
    recommendation: str


def _re(pat: str) -> re.Pattern[str]:
    return re.compile(pat, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule(
        "SG001",
        "Credential or secret file access",
        "high",
        _re(r"(\.ssh/|\.aws/credentials|\.gnupg/|\.env\b|id_rsa|id_ed25519|\.netrc|gcloud|kubeconfig|/etc/passwd|/etc/shadow)"),
        "Do not read private keys, cloud credentials, or .env files. Ask the user to supply only the specific value a task needs.",
    ),
    Rule(
        "SG002",
        "Environment / token exfiltration pattern",
        "high",
        _re(r"(env\s*\||printenv|os\.environ|process\.env|\$[A-Z_]*TOKEN|\$[A-Z_]*API[_-]?KEY|\$[A-Z_]*SECRET|GH_TOKEN|GITHUB_TOKEN)"),
        "Avoid dumping environment variables or tokens. If a token is genuinely needed, name it explicitly and never print or transmit it.",
    ),
    Rule(
        "SG003",
        "Network exfiltration / remote fetch in a skill",
        "high",
        _re(r"(curl\s+[^#\n]*(\||>|-F|-d|--data)|wget\s+[^#\n]*(\||-O| --post)|nc\s+[^#\n]*-e|/dev/tcp/)"),
        "A skill that downloads and pipes, uploads, or opens a raw socket is a classic exfiltration pattern. Remove the network step or make the destination explicit and user-approved.",
    ),
    Rule(
        "SG004",
        "Pipe-to-shell / remote code execution",
        "high",
        _re(r"(curl[^#\n]*\|\s*(ba)?sh|wget[^#\n]*\|\s*(ba)?sh|\|\s*sudo\s+(ba)?sh|eval\s*\(|exec\s*\()"),
        "Never pipe downloaded content into a shell. Download, inspect, then run from a local, reviewed file.",
    ),
    Rule(
        "SG005",
        "Destructive or privilege-escalation command",
        "high",
        _re(r"(rm\s+-[rf]+(\s+/( |$)|(\s+~))|rm\s+-[rf]+\s+\*|chmod\s+777|sudo\s+rm|mkfs\.|dd\s+if=.*of=/dev/)"),
        "Destructive commands need explicit user approval for the exact target. Prefer a dry-run / confirmation step.",
    ),
    Rule(
        "SG006",
        "Obfuscated payload",
        "high",
        _re(r"(base64\s+(-d|--decode)|\$\(base64|from\s+base64\s+import|Buffer\.from\([^,]+,\s*['\"]base64['\"]\)|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){3,}|eval\s*\(\s*atob)"),
        "Base64 / hex blobs that are decoded and executed hide intent. Ship readable code instead, or document exactly what the blob is.",
    ),
    Rule(
        "SG007",
        "Prompt-injection / instruction-override language",
        "medium",
        _re(r"(ignore (all )?(previous|prior|above) instructions|disregard (all )?(previous|prior|above)|you are now|override (your|the) (system|instructions)|do not (tell|reveal|mention|disclose)|bypass (the )?(safety|security|filter|guardrail)|jailbreak|as an ai,?\s+ignore)"),
        "Instruction-override wording in a skill can hijack the host agent. State the task directly instead of telling the agent to ignore other instructions.",
    ),
    Rule(
        "SG008",
        "Suspicious external URL / webhook",
        "medium",
        _re(r"https?://[^\s)\"']*(webhook|ngrok|requestbin|pastebin|transfer\.sh|0x0\.st|file\.io|discord\.com/api/webhooks|hooks\.slack\.com)"),
        "Sending data to a webhook, tunnel, or paste service is rarely needed in a skill. Remove it or document the destination and what is sent.",
    ),
    Rule(
        "SG009",
        "Broad file / history collection",
        "medium",
        _re(r"(find\s+~|find\s+/|cat\s+~\/\.bash_history|cat\s+~\/\.zsh_history|history\s*(\||>)|tar\s+[^#\n]*~|zip\s+-[r]+\s+[^#\n]*~)"),
        "Collecting a whole home directory, shell history, or archive of user files is over-broad. Scope reads to the files the task names.",
    ),
    Rule(
        "SG010",
        "Unpinned / unverified remote install",
        "low",
        _re(r"(npm\s+install\s+-g|pip\s+install\s+[^#\n]*--break-system-packages|npx\s+[a-z0-9@/._-]+|uvx\s+[a-z0-9@/._-]+|git\s+clone\s+https?://)"),
        "Remote installs and clones should be pinned (version / commit) and reviewed. Record the exact source in the skill's documentation.",
    ),
    Rule(
        "SG011",
        "Hardcoded-looking secret",
        "medium",
        _re(r"((ghp_|gho_|github_pat_|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})[A-Za-z0-9_\-]*)"),
        "A token-shaped string is in the file. Remove it, rotate it if it was ever real, and load secrets from the environment instead.",
    ),
    Rule(
        "SG012",
        "Hidden / misleading content",
        "low",
        _re(r"(\u200b|\u200c|\u200d|\ufeff|<!--[^>]{200,})"),
        "Zero-width characters or very long hidden comments can conceal instructions. Keep skill text visible and readable.",
    ),
)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    snippet: str
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {"high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
        }


def _is_scannable(path: Path) -> bool:
    if path.name == LOCKFILE_NAME:
        return False  # The lockfile pins hashes; scanning it would flag itself on every verify.
    if path.name in SKIP_DIRS:
        return False
    if path.suffix.lower() in SCAN_SUFFIXES:
        return True
    return path.name in SCAN_NAMES or path.name == "SKILL.md"


def collect_files(root: Path) -> list[Path]:
    """Collect scannable files under root, skipping VCS/venv dirs.

    Symlinks are not followed, so a crafted skill directory cannot make
    the scanner wander outside the tree being audited.
    """
    files: list[Path] = []
    if root.is_file():
        return [root] if _is_scannable(root) else []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not Path(dirpath, d).is_symlink()]
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            if _is_scannable(p):
                files.append(p)
    return sorted(files)


def scan_file(path: Path, root: Path, allowlist: set[str] | None = None) -> list[Finding]:
    allowlist = allowlist or set()
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError, ValueError):
        return []  # Binary / unreadable files are out of scope for a text scanner.
    findings: list[Finding] = []
    rel = str(path.relative_to(root)) if path != root else path.name
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        # `# skillguard: ignore SG001` suppresses one rule on one line, in the open.
        if "skillguard: ignore" in stripped:
            ignored = {tok.strip() for tok in stripped.split("skillguard: ignore", 1)[1].split(",")}
            ignored = {t for t in ignored if t}
        else:
            ignored = set()
        for rule in RULES:
            if rule.rule_id in allowlist or rule.rule_id in ignored:
                continue
            if rule.pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        file=rel,
                        line=lineno,
                        snippet=stripped[:200],
                        recommendation=rule.recommendation,
                    )
                )
    return findings


def scan_path(root: Path, allowlist: set[str] | None = None) -> ScanResult:
    root = root.resolve()
    result = ScanResult(root=str(root))
    for path in collect_files(root):
        result.files_scanned += 1
        result.findings.extend(scan_file(path, root, allowlist=allowlist))
    return result


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

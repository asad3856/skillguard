"""SARIF 2.1.0 output for SkillGuard findings.

Builds a SARIF log (OASIS SARIF 2.1.0) from a :class:`~skillguard.scanner.ScanResult`
without executing anything that was scanned. The output is intended to be
consumed by SARIF viewers and by GitHub code scanning
(``github/codeql-action/upload-sarif``).

Design notes, and the honest limits that follow from them:

* Severity mapping is the conventional one used by most scanners:
  ``high`` -> ``error``, ``medium`` -> ``warning``, ``low`` -> ``note``.
  An unknown severity maps to ``warning`` rather than silently disappearing.
* Every rule SkillGuard knows about is declared in
  ``tool.driver.rules``, whether or not it fired, so a consumer can see the
  full rule inventory. A finding whose rule id is not in :data:`RULES`
  (for example a hand-built finding) gets a minimal descriptor appended,
  so every result still resolves to a declared rule.
* SkillGuard has no column information: it scans whole lines. Regions
  therefore carry ``startLine`` and the matched line as a snippet, and no
  column fields are invented.
* No numeric ``security-severity`` score is assigned: the rules are
  pattern heuristics with no CVSS-style scoring behind them. The original
  SkillGuard severity is preserved in each result's properties instead.
* Remediation guidance lives in each rule's ``help`` text. A SARIF
  ``fix`` object is deliberately *not* emitted: the schema requires
  ``artifactChanges`` for a fix, and SkillGuard cannot produce a safe
  automated edit for these findings.
* File URIs are relative to the scanned directory, as produced by the
  scanner. When SkillGuard is run from a repository root those URIs line
  up with repository paths; run from elsewhere, a consumer may need to
  rebase them.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import __version__
from .scanner import RULES

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
TOOL_NAME = "SkillGuard"
TOOL_INFORMATION_URI = "https://github.com/asad3856/skillguard"

_SEVERITY_TO_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def severity_to_level(severity) -> str:
    """Map a SkillGuard severity to a SARIF ``level``.

    Unknown, empty, or non-string severities map to ``warning``: the
    finding stays visible instead of being dropped or mislabelled.
    """
    if isinstance(severity, str):
        return _SEVERITY_TO_LEVEL.get(severity.strip().lower(), "warning")
    return "warning"


def _clean_text(value, fallback: str = "") -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return fallback
    return str(value)


def _coerce_line(line) -> int:
    """Return a SARIF-valid line number (>= 1) for any input.

    SARIF line numbers are 1-based. Scanner findings always carry a real
    line, but hand-built or malformed findings must not crash output or
    produce an invalid ``startLine`` of 0 or less.
    """
    if isinstance(line, bool):
        return 1
    try:
        number = int(line)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return 1
    return number if number >= 1 else 1


def _sarif_uri(file, root=None):
    """Normalise a finding's file path to a SARIF artifact URI.

    Returns ``None`` when there is no usable location, in which case the
    result omits ``locations`` entirely (valid SARIF for a finding with
    no file/line). Backslashes become forward slashes, a leading ``./``
    is stripped, and an absolute path under the scan root becomes
    relative to that root.
    """
    if file is None:
        return None
    if isinstance(file, Path):
        text = str(file)
    elif isinstance(file, str):
        text = file
    else:
        text = str(file)
    text = text.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if not text:
        return None
    if root:
        try:
            root_path = Path(root)
            file_path = Path(text)
            if file_path.is_absolute():
                relative = file_path.relative_to(root_path)
                text = str(relative).replace("\\", "/")
        except (ValueError, TypeError, RuntimeError):
            pass
    return text


def _descriptor(rule_id: str, title: str, severity, recommendation: str) -> dict:
    title = _clean_text(title, fallback="").strip() or rule_id
    recommendation = _clean_text(recommendation, fallback="").strip()
    severity_text = _clean_text(severity, fallback="").strip().lower() or "unknown"
    help_text = recommendation or title
    full_text = title if not recommendation else f"{title}. {recommendation}"
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": title},
        "fullDescription": {"text": full_text},
        "help": {"text": help_text, "markdown": help_text},
        "defaultConfiguration": {"level": severity_to_level(severity)},
        "properties": {"tags": ["security"], "skillguard/severity": severity_text},
    }


def _finding_fields(finding):
    """Read finding fields from a Finding object or a plain dict."""
    if isinstance(finding, dict):
        get = finding.get
    else:
        get = lambda name, default=None: getattr(finding, name, default)  # noqa: E731
    return {
        "rule_id": _clean_text(get("rule_id"), fallback=""),
        "title": _clean_text(get("title"), fallback=""),
        "severity": get("severity"),
        "file": get("file"),
        "line": get("line"),
        "snippet": _clean_text(get("snippet"), fallback=""),
        "recommendation": _clean_text(get("recommendation"), fallback=""),
    }


def _fingerprint(fields: dict) -> str:
    payload = "|".join(
        [
            fields["rule_id"],
            _sarif_uri(fields["file"]) or "",
            str(_coerce_line(fields["line"])),
            fields["snippet"],
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def to_sarif(result) -> dict:
    """Convert a scan result to a SARIF 2.1.0 log document (dict)."""
    if isinstance(result, dict):
        findings = result.get("findings", []) or []
        root = result.get("root", "")
        files_scanned = result.get("files_scanned")
    else:
        findings = getattr(result, "findings", []) or []
        root = getattr(result, "root", "")
        files_scanned = getattr(result, "files_scanned", None)

    descriptors: list[dict] = []
    rule_index: dict[str, int] = {}
    for rule in RULES:
        rule_index[rule.rule_id] = len(descriptors)
        descriptors.append(
            _descriptor(rule.rule_id, rule.title, rule.severity, rule.recommendation)
        )

    results: list[dict] = []
    for finding in findings:
        fields = _finding_fields(finding)
        rule_id = fields["rule_id"] or "SG000"
        if rule_id not in rule_index:
            rule_index[rule_id] = len(descriptors)
            descriptors.append(
                _descriptor(
                    rule_id,
                    fields["title"],
                    fields["severity"],
                    fields["recommendation"],
                )
            )
        title = fields["title"].strip() or rule_id
        snippet = fields["snippet"].strip()
        message_text = f"{title}: {snippet}" if snippet else title
        sarif_result: dict = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": severity_to_level(fields["severity"]),
            "message": {"text": message_text},
        }
        uri = _sarif_uri(fields["file"], root=root)
        if uri is not None:
            region: dict = {"startLine": _coerce_line(fields["line"])}
            if snippet:
                region["snippet"] = {"text": snippet}
            sarif_result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": region,
                    }
                }
            ]
        sarif_result["partialFingerprints"] = {"skillguard/v1": _fingerprint(fields)}
        properties: dict = {
            "skillguard/severity": _clean_text(fields["severity"], fallback="")
            .strip()
            .lower()
            or "unknown"
        }
        if fields["recommendation"].strip():
            properties["skillguard/recommendation"] = fields["recommendation"].strip()
        sarif_result["properties"] = properties
        results.append(sarif_result)

    run: dict = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": TOOL_INFORMATION_URI,
                "rules": descriptors,
            }
        },
        "results": results,
    }
    run_properties: dict = {}
    if isinstance(files_scanned, int) and not isinstance(files_scanned, bool):
        run_properties["skillguard/filesScanned"] = files_scanned
    if root:
        run_properties["skillguard/root"] = _clean_text(root)
    if run_properties:
        run["properties"] = run_properties
    return {"$schema": SARIF_SCHEMA_URI, "version": SARIF_VERSION, "runs": [run]}


def to_sarif_json(result, indent: int = 2) -> str:
    """Render a scan result as a SARIF 2.1.0 JSON string."""
    return json.dumps(to_sarif(result), indent=indent, ensure_ascii=False)


__all__ = [
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "TOOL_INFORMATION_URI",
    "TOOL_NAME",
    "severity_to_level",
    "to_sarif",
    "to_sarif_json",
]

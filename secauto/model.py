"""Modèle de données unifié de la plateforme secauto."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "info"]

_SEVERITY_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "blocker": "critical",
    "high": "high",
    "error": "high",
    "major": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "warn": "medium",
    "low": "low",
    "minor": "low",
    "note": "info",
    "info": "info",
    "informational": "info",
    "unknown": "info",
}


def normalize_severity(value: Any) -> str:
    """Ramène les échelles de sévérité hétérogènes des outils à 5 niveaux."""
    if value is None:
        return "info"
    text = str(value).strip().lower()
    if text in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[text]
    for key, mapped in _SEVERITY_ALIASES.items():
        if key in text:
            return mapped
    return "info"


def normalize_cwe(values: Any) -> list[str]:
    """Accepte 'CWE-89', 'CWE-89: SQL Injection', [89], ['cwe-89'] → ['CWE-89']."""
    if values is None:
        return []
    if isinstance(values, (str, int)):
        values = [values]
    out: list[str] = []
    for value in values:
        if isinstance(value, int):
            out.append(f"CWE-{value}")
            continue
        text = str(value).strip()
        if text.upper().startswith("CWE-"):
            num = text[4:].split(":")[0].split()[0]
            out.append(f"CWE-{num}")
        elif text.isdigit():
            out.append(f"CWE-{text}")
    return sorted(set(out))


def normalize_owasp(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    out = []
    for value in values:
        text = str(value).strip()
        if text:
            out.append(text)
    return sorted(set(out))


@dataclass
class Finding:
    """Un résultat d'analyse, indépendant de l'outil qui l'a produit."""

    tool: str
    category: str          # SAST | DAST | SCA | CUSTOM
    target: str
    title: str
    severity: str = "info"
    description: str = ""
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    rule_id: str = ""
    file: str = ""
    line: int | None = None
    endpoint: str = ""
    evidence: str = ""
    raw_ref: str = ""

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.cwe = normalize_cwe(self.cwe)
        self.owasp = normalize_owasp(self.owasp)
        for attribute in (
            "tool", "category", "target", "title", "description",
            "rule_id", "file", "endpoint", "evidence", "raw_ref",
        ):
            value = getattr(self, attribute)
            if value is not None and not isinstance(value, str):
                setattr(self, attribute, str(value))
        if self.line is not None:
            try:
                self.line = int(self.line)
            except (TypeError, ValueError):
                self.line = None

    @property
    def fingerprint(self) -> str:
        """Identité stable d'un résultat, utilisée pour le diff avant/après."""
        basis = "|".join(
            [
                self.tool,
                self.target,
                self.rule_id or self.title,
                self.file,
                str(self.line or ""),
                self.endpoint,
            ]
        )
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in allowed})


def load_findings(path) -> list[Finding]:
    payload = json.loads(open(path, encoding="utf-8").read())
    if isinstance(payload, dict):
        payload = payload.get("findings", [])
    return [Finding.from_dict(item) for item in payload]


def dump_findings(findings: list[Finding], path) -> None:
    payload = {
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Un même défaut peut être remonté par plusieurs règles : on fusionne."""
    seen: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint
        if key not in seen:
            seen[key] = finding
            continue
        kept = seen[key]
        kept.cwe = sorted(set(kept.cwe) | set(finding.cwe))
        kept.owasp = sorted(set(kept.owasp) | set(finding.owasp))
        if not kept.evidence and finding.evidence:
            kept.evidence = finding.evidence
    return list(seen.values())


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITIES.index(f.severity), f.tool, f.title),
    )

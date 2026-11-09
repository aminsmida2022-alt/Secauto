#!/usr/bin/env python3
"""Conversion des résultats normalisés secauto vers SARIF 2.1.0.

Permet l'upload dans GitHub code scanning (onglet Security > Code scanning).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--out", default="secauto.sarif")
    args = parser.parse_args()

    findings_path = Path(args.run_dir) / "findings.json"
    payload = json.loads(findings_path.read_text(encoding="utf-8"))
    findings = payload.get("findings", [])

    rules: dict[str, dict] = {}
    results = []

    for finding in findings:
        rule_id = f"{finding['tool']}:{finding.get('rule_id') or finding['title']}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding["title"][:120],
                "shortDescription": {"text": finding["title"][:200]},
                "fullDescription": {"text": finding.get("description", "")[:1000]},
                "properties": {
                    "tags": ["security"] + finding.get("cwe", []) + finding.get("owasp", []),
                    "security-severity": SECURITY_SEVERITY.get(finding["severity"], "0.0"),
                },
            },
        )

        location = finding.get("file") or finding.get("endpoint") or ""
        artifact = {"uri": location.split(":")[0] if location else "unknown"}
        physical = {"artifactLocation": artifact}
        if finding.get("line"):
            physical["region"] = {"startLine": int(finding["line"])}

        results.append(
            {
                "ruleId": rule_id,
                "level": LEVELS.get(finding["severity"], "note"),
                "message": {
                    "text": f"[{finding['tool']}] {finding['title']} — {finding.get('evidence', '')}"
                },
                "locations": [{"physicalLocation": physical}],
                "partialFingerprints": {"secauto/v1": finding.get("fingerprint", "")},
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "secauto", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    Path(args.out).write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"SARIF écrit : {args.out} ({len(results)} résultats)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Alertes : signaler les constats qui dépassent un seuil de sévérité.

Une exécution produit un fichier findings.json ; si des constats atteignent
le seuil (défaut : high), l'alerte est matérialisée par :
  - un fichier alerts.md archivé à côté des autres rapports ;
  - un rendu Markdown affichable dans la CI ($GITHUB_STEP_SUMMARY) ;
  - un code de sortie 1 pour la commande CLI (comme --fail-on).
Le workflow GitHub Actions agrège ces alertes et ouvre une issue GitHub.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .model import SEVERITIES

_LEVELS = {sev: idx for idx, sev in enumerate(SEVERITIES)}


def collect(run_dir: Path, threshold: str = "high") -> dict[str, Any]:
    """Retourne les constats au niveau du seuil ou plus sévères."""
    findings_file = run_dir / "findings.json"
    findings: list[dict[str, Any]] = []
    if findings_file.exists():
        payload = json.loads(findings_file.read_text(encoding="utf-8"))
        findings = payload.get("findings", []) if isinstance(payload, dict) else payload
    limit = _LEVELS.get(threshold, _LEVELS["high"])
    blocking = [
        f for f in findings
        if _LEVELS.get(f.get("severity", "info"), len(SEVERITIES)) <= limit
    ]
    return {
        "target": run_dir.parent.name,
        "run_id": run_dir.name,
        "threshold": threshold,
        "total_findings": len(findings),
        "blocking": blocking,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }


def render_markdown(alerts: dict[str, Any]) -> str:
    """Rendu Markdown de l'alerte (adapté au job summary GitHub)."""
    lines: list[str] = []
    blocking = alerts["blocking"]
    if blocking:
        lines.append(
            f"## 🔴 Alerte — {len(blocking)} constat(s) au niveau "
            f"« {alerts['threshold']} » ou plus"
        )
        lines.append("")
        lines.append("| Sévérité | Titre | Outil | Endpoint / Fichier | CWE |")
        lines.append("|---|---|---|---|---|")
        for f in blocking:
            lines.append(
                f"| {f.get('severity', 'info')} "
                f"| {f.get('title', '')} "
                f"| `{f.get('tool', '')}` "
                f"| `{f.get('endpoint') or f.get('file') or '—'}` "
                f"| {', '.join(f.get('cwe') or []) or '—'} |"
            )
    else:
        lines.append(
            f"## 🟢 Aucune alerte — aucun constat au niveau "
            f"« {alerts['threshold']} » ou plus"
        )
    lines.append("")
    lines.append(
        f"*Cible : **{alerts['target']}** · exécution : `{alerts['run_id']}` · "
        f"{alerts['total_findings']} constats analysés · "
        f"généré le {alerts['generated_at']}*"
    )
    return "\n".join(lines)


def emit(run_dir: Path, threshold: str = "high") -> dict[str, Any]:
    """Collecte, archive alerts.md dans le répertoire d'exécution, retourne."""
    alerts = collect(run_dir, threshold)
    out = run_dir / "alerts.md"
    out.write_text(render_markdown(alerts), encoding="utf-8")
    alerts["path"] = str(out)
    return alerts

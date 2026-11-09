"""Génération des rapports HTML et Markdown."""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .model import SEVERITIES, Finding

SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#0369a1",
    "info": "#4b5563",
}

CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
       background:#f6f7f9; color:#111827; line-height:1.5; }
header { background:#0f172a; color:#fff; padding:32px 40px; }
header h1 { margin:0 0 6px; font-size:24px; }
header p { margin:0; color:#94a3b8; font-size:14px; }
main { max-width:1200px; margin:0 auto; padding:28px 24px 60px; }
section { margin-bottom:36px; }
h2 { font-size:18px; margin:0 0 14px; padding-bottom:8px; border-bottom:1px solid #e5e7eb; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }
.card { background:#fff; border:1px solid #e5e7eb; border-radius:10px; padding:16px 18px; }
.card .label { font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:#6b7280; }
.card .value { font-size:28px; font-weight:650; margin-top:4px; }
table { width:100%; border-collapse:collapse; background:#fff; border:1px solid #e5e7eb;
        border-radius:10px; overflow:hidden; font-size:14px; }
th, td { text-align:left; padding:9px 12px; border-bottom:1px solid #f0f1f3; vertical-align:top; }
th { background:#f9fafb; font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:#6b7280; }
tr:last-child td { border-bottom:none; }
td.num { text-align:right; font-variant-numeric:tabular-nums; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; color:#fff; font-size:11px;
         font-weight:600; text-transform:uppercase; letter-spacing:.03em; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12.5px; }
.ev { color:#374151; background:#f3f4f6; padding:2px 6px; border-radius:4px; display:inline-block;
      max-width:100%; overflow-wrap:anywhere; }
.empty { color:#6b7280; font-style:italic; padding:14px 0; }
details { background:#fff; border:1px solid #e5e7eb; border-radius:10px; margin-bottom:10px; }
summary { cursor:pointer; padding:12px 16px; font-weight:600; }
details .body { padding:0 16px 16px; font-size:14px; color:#374151; }
footer { max-width:1200px; margin:0 auto; padding:0 24px 40px; color:#9ca3af; font-size:12px; }
"""


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
    return f'<span class="badge" style="background:{color}">{_esc(severity)}</span>'


def _table(headers: list[str], rows: list[list[str]], numeric: set[int] | None = None) -> str:
    numeric = numeric or set()
    out = ["<table><thead><tr>"]
    for header in headers:
        out.append(f"<th>{_esc(header)}</th>")
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>")
        for index, cell in enumerate(row):
            css = ' class="num"' if index in numeric else ""
            out.append(f"<td{css}>{cell}</td>")
        out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def render_html(
    target: str,
    run_id: str,
    findings: list[Finding],
    evaluation: dict[str, Any],
    errors: list[str],
) -> str:
    overall = evaluation["overall"]
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITIES}

    parts: list[str] = []
    parts.append("<!DOCTYPE html><html lang='fr'><head><meta charset='utf-8'>")
    parts.append(f"<title>secauto — {_esc(target)} — {_esc(run_id)}</title>")
    parts.append(f"<style>{CSS}</style></head><body>")
    parts.append("<header>")
    parts.append("<h1>Rapport de sécurité applicative automatisé</h1>")
    parts.append(
        f"<p>Cible <strong>{_esc(target)}</strong> · exécution {_esc(run_id)} · "
        f"généré le {datetime.now().strftime('%d/%m/%Y %H:%M')} · secauto</p>"
    )
    parts.append("</header><main>")

    parts.append("<section><h2>Synthèse</h2><div class='cards'>")
    for label, value in [
        ("Résultats", len(findings)),
        ("Critiques", counts["critical"]),
        ("Élevés", counts["high"]),
        ("Moyens", counts["medium"]),
        ("Faibles", counts["low"]),
        ("Vérité terrain", evaluation["ground_truth_count"]),
        ("Rappel", f"{overall['recall']:.0%}" if evaluation["ground_truth_count"] else "—"),
        ("Précision", f"{overall['precision']:.0%}" if findings else "—"),
    ]:
        parts.append(f"<div class='card'><div class='label'>{_esc(label)}</div>"
                     f"<div class='value'>{_esc(value)}</div></div>")
    parts.append("</div></section>")

    if evaluation["ground_truth_count"]:
        parts.append("<section><h2>Capacité de détection par outil</h2>")
        rows = []
        for tool, stats in sorted(evaluation["per_tool"].items()):
            rows.append([
                f"<code>{_esc(tool)}</code>",
                str(stats["findings"]),
                str(stats["tp"]),
                str(stats["fp"]),
                f"{stats['precision']:.0%}",
                f"{stats.get('recall', 0):.0%}",
            ])
        parts.append(
            _table(
                ["Outil", "Résultats", "Vrais positifs", "Faux positifs", "Précision", "Rappel"],
                rows,
                numeric={1, 2, 3, 4, 5},
            )
        )
        parts.append(
            f"<p style='color:#6b7280;font-size:13px;margin-top:10px'>"
            f"Rappel global : <strong>{overall['recall']:.0%}</strong> "
            f"({evaluation['ground_truth_count'] - overall['fn']}/{evaluation['ground_truth_count']} "
            f"vulnérabilités connues détectées) · F1 : <strong>{overall['f1']:.3f}</strong></p>"
        )
        if evaluation["missed"]:
            parts.append("<p style='font-size:13px'><strong>Non détectées :</strong> "
                         + ", ".join(f"<code>{_esc(m)}</code>" for m in evaluation["missed"])
                         + "</p>")
        parts.append("</section>")

    if errors:
        parts.append("<section><h2>Outils en erreur</h2><ul>")
        for error in errors:
            parts.append(f"<li><code>{_esc(error)}</code></li>")
        parts.append("</ul></section>")

    by_category: dict[str, list[Finding]] = {}
    for finding in findings:
        by_category.setdefault(finding.category, []).append(finding)

    titles = {
        "SAST": "Analyse statique (SAST)",
        "DAST": "Analyse dynamique (DAST)",
        "SCA": "Composition logicielle (SCA)",
        "CUSTOM": "Détection complémentaire",
    }
    for category in ["SAST", "DAST", "SCA", "CUSTOM"]:
        items = by_category.get(category, [])
        parts.append(f"<section><h2>{_esc(titles.get(category, category))} "
                     f"<span style='color:#9ca3af;font-weight:400'>({len(items)})</span></h2>")
        if not items:
            parts.append("<p class='empty'>Aucun résultat.</p></section>")
            continue
        rows = []
        for finding in items:
            location = finding.endpoint or finding.file or "—"
            rows.append([
                _badge(finding.severity),
                f"<strong>{_esc(finding.title)}</strong><br>"
                f"<span style='color:#6b7280;font-size:12.5px'>{_esc(finding.tool)}"
                f"{' · ' + _esc(', '.join(finding.cwe)) if finding.cwe else ''}</span>",
                f"<span class='mono'>{_esc(location)}</span>",
                f"<span class='ev'>{_esc(finding.evidence[:180])}</span>" if finding.evidence else "",
            ])
        parts.append(_table(["Sév.", "Constat", "Localisation", "Preuve"], rows))
        parts.append("</section>")

    parts.append("<section><h2>Détail exploitable</h2>")
    parts.append("<details><summary>Afficher le JSON normalisé</summary><div class='body'>")
    payload = json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False)
    parts.append(f"<pre class='mono' style='overflow:auto;max-height:520px'>{_esc(payload)}</pre>")
    parts.append("</div></details></section>")
    parts.append("</main>")
    parts.append("<footer>secauto — plateforme d'évaluation automatisée de la détection de "
                 "vulnérabilités · SAST / DAST / SCA / règles personnalisées</footer>")
    parts.append("</body></html>")
    return "".join(parts)


def render_markdown(
    target: str,
    run_id: str,
    findings: list[Finding],
    evaluation: dict[str, Any],
    errors: list[str],
) -> str:
    overall = evaluation["overall"]
    lines = [
        f"# Rapport secauto — {target}",
        "",
        f"- Exécution : `{run_id}`",
        f"- Date : {datetime.now().strftime('%d/%m/%Y %H:%M')}",
        f"- Résultats : **{len(findings)}**",
        f"- Rappel : **{overall['recall']:.0%}** · Précision : **{overall['precision']:.0%}** · F1 : **{overall['f1']:.3f}**",
        "",
        "## Résultats par outil",
        "",
        "| Outil | Résultats | TP | FP | Précision | Rappel |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    has_gt = bool(evaluation["ground_truth_count"])
    for tool, stats in sorted(evaluation["per_tool"].items()):
        lines.append(
            f"| `{tool}` | {stats['findings']} | {stats['tp']} | {stats['fp']} "
            f"| {stats['precision']:.0%} | {stats.get('recall', 0):.0%} |"
        )
    if not has_gt:
        lines += [
            "",
            "> Aucune vérité terrain n'est définie pour cette cible : "
            "précision et rappel ne sont pas interprétables.",
        ]
    lines += ["", "## Constats", ""]
    for severity in SEVERITIES:
        items = [f for f in findings if f.severity == severity]
        if not items:
            continue
        lines.append(f"### {severity.upper()} ({len(items)})")
        lines.append("")
        for finding in items:
            location = finding.endpoint or finding.file or "—"
            cwe = f" · {', '.join(finding.cwe)}" if finding.cwe else ""
            lines.append(f"- **{finding.title}** — `{finding.tool}`{cwe} — `{location}`")
        lines.append("")
    if errors:
        lines += ["## Outils en erreur", ""] + [f"- `{e}`" for e in errors] + [""]
    return "\n".join(lines)


def write_reports(
    run_dir: Path,
    target: str,
    run_id: str,
    findings: list[Finding],
    evaluation: dict[str, Any],
    errors: list[str],
) -> dict[str, str]:
    html_path = run_dir / "report.html"
    md_path = run_dir / "summary.md"
    html_path.write_text(
        render_html(target, run_id, findings, evaluation, errors), encoding="utf-8"
    )
    md_path.write_text(
        render_markdown(target, run_id, findings, evaluation, errors), encoding="utf-8"
    )
    return {"html": str(html_path), "markdown": str(md_path)}

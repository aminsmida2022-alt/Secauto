"""Évaluation de la capacité de détection (TP / FP / FN, précision, rappel)."""

from __future__ import annotations

import re
from typing import Any

from .config import load_ground_truth
from .model import Finding


def _regex_matches(pattern: str, value: str) -> bool:
    if not pattern:
        return False
    return re.search(pattern, value or "", re.IGNORECASE) is not None


def finding_matches(gt: dict[str, Any], finding: Finding) -> bool:
    """Décide si un résultat correspond à une vulnérabilité de la vérité terrain."""
    match = gt.get("match", {}) or {}

    if match.get("title"):
        return _regex_matches(match["title"], finding.title)
    if match.get("rule"):
        return _regex_matches(match["rule"], finding.rule_id)

    gt_cwe = {c.upper() for c in gt.get("cwe", []) or []}
    if gt_cwe:
        if not gt_cwe & {c.upper() for c in finding.cwe}:
            return False

    # Les localisations sont des alternatives : un constat SAST est localisé par
    # fichier, un constat DAST par endpoint. L'un OU l'autre suffit.
    location_ok = False
    if match.get("endpoint") and _regex_matches(match["endpoint"], finding.endpoint):
        location_ok = True
    if match.get("file") and _regex_matches(match["file"], finding.file):
        location_ok = True
    if (match.get("endpoint") or match.get("file")) and not location_ok:
        return False

    if match.get("tool") and not _regex_matches(match["tool"], finding.tool):
        return False

    # Sans CWE ni localisation, aucun critère ne permet d'affirmer la correspondance.
    if not gt_cwe and not match.get("endpoint") and not match.get("file"):
        return False
    return True


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 3) if denominator else 0.0


def evaluate(findings: list[Finding], target: str) -> dict[str, Any]:
    gt = load_ground_truth(target)
    matched_gt: dict[str, list[str]] = {item["id"]: [] for item in gt}
    tp_flags: dict[str, bool] = {f.fingerprint: False for f in findings}
    tool_gt: dict[str, set[str]] = {}

    for item in gt:
        for finding in findings:
            if finding_matches(item, finding):
                matched_gt[item["id"]].append(f"{finding.tool}:{finding.fingerprint}")
                tp_flags[finding.fingerprint] = True
                tool_gt.setdefault(finding.tool, set()).add(item["id"])

    tp = sum(1 for flag in tp_flags.values() if flag)
    fp = len(findings) - tp
    fn = sum(1 for ids in matched_gt.values() if not ids)
    total_gt = len(gt)

    per_tool: dict[str, dict[str, Any]] = {}
    for finding in findings:
        bucket = per_tool.setdefault(
            finding.tool, {"findings": 0, "tp": 0, "fp": 0, "by_severity": {}}
        )
        bucket["findings"] += 1
        bucket["by_severity"][finding.severity] = bucket["by_severity"].get(finding.severity, 0) + 1
        if tp_flags[finding.fingerprint]:
            bucket["tp"] += 1
        else:
            bucket["fp"] += 1

    for tool, bucket in per_tool.items():
        bucket["precision"] = _ratio(bucket["tp"], bucket["findings"])
        bucket["fp_rate"] = _ratio(bucket["fp"], bucket["findings"])
        # Rappel de l'outil = part de la vérité terrain qu'il a couverte à lui seul.
        bucket["recall"] = _ratio(len(tool_gt.get(tool, set())), total_gt)

    by_category: dict[str, dict[str, Any]] = {}
    for finding in findings:
        bucket = by_category.setdefault(finding.category, {"findings": 0, "tp": 0, "fp": 0})
        bucket["findings"] += 1
        if tp_flags[finding.fingerprint]:
            bucket["tp"] += 1
        else:
            bucket["fp"] += 1
    for bucket in by_category.values():
        bucket["precision"] = _ratio(bucket["tp"], bucket["findings"])

    return {
        "target": target,
        "ground_truth_count": total_gt,
        "findings_count": len(findings),
        "overall": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(total_gt - fn, total_gt),
            "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        },
        "per_tool": per_tool,
        "per_category": by_category,
        "matched": {
            item_id: ids for item_id, ids in matched_gt.items() if ids
        },
        "missed": [item for item, ids in matched_gt.items() if not ids],
        "ground_truth": [
            {"id": item["id"], "title": item.get("title", ""), "cwe": item.get("cwe", [])}
            for item in gt
        ],
    }


def diff_runs(before: list[Finding], after: list[Finding]) -> dict[str, Any]:
    """Compare deux exécutions par empreinte : nouvelles, corrigées, persistantes."""
    before_map = {f.fingerprint: f for f in before}
    after_map = {f.fingerprint: f for f in after}
    return {
        "new": [after_map[k].to_dict() for k in after_map.keys() - before_map.keys()],
        "fixed": [before_map[k].to_dict() for k in before_map.keys() - after_map.keys()],
        "persistent": [after_map[k].to_dict() for k in after_map.keys() & before_map.keys()],
    }

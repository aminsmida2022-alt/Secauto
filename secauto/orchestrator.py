"""Orchestration d'une campagne d'analyse."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from . import metrics
from .config import REPORT_DIR, get_target
from .model import SEVERITIES, deduplicate, dump_findings, load_findings, sort_findings
from .report import write_reports
from .runners import RunnerError, build_runner

DEFAULT_TOOLS = ["sast", "sca", "sca-npm", "dast", "custom"]


def new_run_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _update_index(entry: dict[str, Any]) -> None:
    index_path = REPORT_DIR / "index.json"
    data: list[dict[str, Any]] = []
    if index_path.exists():
        try:
            data = json.loads(index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = []
    data = [item for item in data if not (
        item.get("target") == entry["target"] and item.get("run_id") == entry["run_id"]
    )]
    data.append(entry)
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def run(
    target_name: str,
    tools: list[str] | None = None,
    run_id: str | None = None,
    offline: bool = False,
    fail_on: str | None = None,
) -> dict[str, Any]:
    target = get_target(target_name)
    tools = tools or DEFAULT_TOOLS
    run_id = run_id or new_run_id()

    run_dir = REPORT_DIR / target_name / run_id
    (run_dir / "raw").mkdir(parents=True, exist_ok=True)

    print(f"\n=== secauto — cible: {target_name} — run: {run_id} ===")
    print(f"    répertoire : {run_dir}")

    findings = []
    errors: list[str] = []
    executed: list[str] = []

    for tool in tools:
        runner = build_runner(tool, {"offline": offline})
        if runner is None:
            errors.append(f"{tool}: outil inconnu")
            print(f"   [!] outil inconnu : {tool}")
            continue
        if not runner.available():
            message = f"{tool}: indisponible — {runner.missing_hint()}"
            errors.append(message)
            print(f"   [!] {message}")
            continue
        print(f"   [>] {tool}…")
        try:
            findings.extend(runner.run(target_name, target, run_dir))
            executed.append(tool)
        except RunnerError as exc:
            errors.append(f"{tool}: {exc}")
            print(f"   [!] {tool} : {exc}")
        except Exception as exc:  # robustesse : un outil ne doit pas casser la campagne
            errors.append(f"{tool}: erreur inattendue — {exc}")
            print(f"   [!] {tool} : erreur inattendue — {exc}")

    findings = sort_findings(deduplicate(findings))
    dump_findings(findings, run_dir / "findings.json")

    evaluation = metrics.evaluate(findings, target_name)
    (run_dir / "metrics.json").write_text(
        json.dumps(evaluation, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    paths = write_reports(run_dir, target_name, run_id, findings, evaluation, errors)

    entry = {
        "target": target_name,
        "run_id": run_id,
        "date": datetime.now().isoformat(timespec="seconds"),
        "tools": executed,
        "errors": errors,
        "findings": len(findings),
        "by_severity": {
            sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITIES
        },
        "metrics": evaluation["overall"],
        "reports": paths,
    }
    _update_index(entry)

    print("\n   Résumé :")
    for sev in SEVERITIES:
        count = entry["by_severity"][sev]
        if count:
            print(f"     {sev:<9} {count}")
    print(f"     rappel   {evaluation['overall']['recall']:.0%} "
          f"| précision {evaluation['overall']['precision']:.0%}")
    print(f"     rapport  {paths['html']}")

    if fail_on:
        threshold = SEVERITIES.index(fail_on) if fail_on in SEVERITIES else 0
        blocking = [f for f in findings if SEVERITIES.index(f.severity) <= threshold]
        entry["blocking"] = len(blocking)
        if blocking:
            print(f"   [x] {len(blocking)} résultat(s) au niveau {fail_on} ou supérieur")
            entry["exit_code"] = 1
        else:
            entry["exit_code"] = 0

    return entry


def compare(target_name: str, before: str, after: str) -> dict[str, Any]:
    before_dir = REPORT_DIR / target_name / before
    after_dir = REPORT_DIR / target_name / after
    for path in (before_dir, after_dir):
        if not path.exists():
            raise FileNotFoundError(f"exécution introuvable : {path}")
    result = metrics.diff_runs(
        load_findings(before_dir / "findings.json"),
        load_findings(after_dir / "findings.json"),
    )
    result.update({"target": target_name, "before": before, "after": after})
    out = REPORT_DIR / target_name / f"diff-{before}-{after}.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    result["path"] = str(out)
    return result

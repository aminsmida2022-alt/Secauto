"""Chargement de la configuration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
REPORT_DIR = Path(os.environ.get("SECAUTO_REPORTS", ROOT / "reports"))


def load_targets() -> dict[str, Any]:
    path = CONFIG_DIR / "targets.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data.get("targets", {})


def get_target(name: str) -> dict[str, Any]:
    targets = load_targets()
    if name not in targets:
        known = ", ".join(targets) or "(aucune)"
        raise KeyError(f"cible inconnue : {name}. Cibles disponibles : {known}")
    return targets[name]


def resolve(path: str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else ROOT / candidate


def load_ground_truth(target: str) -> list[dict[str, Any]]:
    path = ROOT / "metrics" / "ground_truth" / f"{target}.yaml"
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data.get("vulnerabilities", [])

"""Interface en ligne de commande de secauto."""

from __future__ import annotations

import argparse
import json
import sys

from .config import load_targets
from .orchestrator import DEFAULT_TOOLS, compare, run
from .runners import RUNNERS


def cmd_list_targets(_: argparse.Namespace) -> int:
    targets = load_targets()
    print(f"{'Cible':<16} {'Type':<6} URL")
    print("-" * 60)
    for name, cfg in targets.items():
        print(f"{name:<16} {cfg.get('kind', '?'):<6} {cfg.get('base_url', '')}")
    return 0


def cmd_list_tools(_: argparse.Namespace) -> int:
    for name, cls in RUNNERS.items():
        print(f"{name:<10} {cls.category:<10} {cls.__name__}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    tools = [t.strip() for t in args.tools.split(",") if t.strip()] if args.tools else DEFAULT_TOOLS
    entry = run(
        target_name=args.target,
        tools=tools,
        run_id=args.run_id,
        offline=args.offline,
        fail_on=args.fail_on,
    )
    return int(entry.get("exit_code", 0))


def cmd_compare(args: argparse.Namespace) -> int:
    result = compare(args.target, args.before, args.after)
    print(
        f"Nouvelles : {len(result['new'])} · "
        f"Corrigées : {len(result['fixed'])} · "
        f"Persistantes : {len(result['persistent'])}"
    )
    print(f"Détail : {result['path']}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    print(json.dumps(load_targets().get(args.target, {}), indent=2, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secauto",
        description="Plateforme automatisée de détection de vulnérabilités (SAST / DAST / SCA / custom).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-targets", help="afficher les cibles configurées").set_defaults(
        func=cmd_list_targets
    )
    sub.add_parser("list-tools", help="afficher les outils disponibles").set_defaults(
        func=cmd_list_tools
    )

    run_parser = sub.add_parser("run", help="lancer une campagne d'analyse")
    run_parser.add_argument("--target", required=True, help="nom de la cible (config/targets.yaml)")
    run_parser.add_argument(
        "--tools",
        default=",".join(DEFAULT_TOOLS),
        help=f"outils à exécuter, séparés par des virgules (défaut : {','.join(DEFAULT_TOOLS)})",
    )
    run_parser.add_argument("--run-id", help="identifiant d'exécution (défaut : horodatage)")
    run_parser.add_argument("--offline", action="store_true", help="désactiver les packs Semgrep distants")
    run_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="code de sortie 1 si un résultat atteint ce niveau (usage CI)",
    )
    run_parser.set_defaults(func=cmd_run)

    compare_parser = sub.add_parser("compare", help="comparer deux exécutions (avant/après)")
    compare_parser.add_argument("--target", required=True)
    compare_parser.add_argument("--before", required=True, help="run-id de référence")
    compare_parser.add_argument("--after", required=True, help="run-id à comparer")
    compare_parser.set_defaults(func=cmd_compare)

    show_parser = sub.add_parser("show", help="afficher la configuration d'une cible")
    show_parser.add_argument("--target", required=True)
    show_parser.set_defaults(func=cmd_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

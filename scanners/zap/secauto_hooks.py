# -*- coding: utf-8 -*-
"""Scripts ZAP personnalisés — hooks pour zap-baseline.py.

Ce fichier est chargé par zap-baseline.py (image docker zaproxy) quand le
runner ZAP de secauto passe ``--hook=/zap/wrk/hooks/secauto_hooks.py``.
Le drapeau ``--hook`` bascule zap-baseline.py hors du framework
d'automatisation vers le flux « legacy », qui déclenche les hooks :

    cli_opts(opts)                    <- parsing des options
    zap_started(zap, target)          <- ZAP démarré, cible accessible
    pre_exit(fail, warn, pass)        <- juste avant la sortie

Ici, le hook ``zap_started`` réalise des sondes HTTP ciblées que les règles
passives ZAP ne couvrent pas (fichier .env exposé, dépôt .git accessible,
Spring Boot Actuator ouvert, stack trace sur une page d'erreur) puis :
  1. ajoute les alertes dans ZAP (API ``alert.add``) pour qu'elles figurent
     dans les rapports JSON/HTML/MD générés par le baseline scan ;
  2. écrit un rapport ``zap-custom.json`` dans le répertoire monté
     (/zap/wrk) au format contractuel de secauto, relu et fusionné par
     le runner (secauto/runners.py, ZapRunner).

Compatible Python 2/3 : l'image ZAP embarque les deux interpréteurs.
"""

import json
import os
import re
import sys

try:  # Python 3
    from urllib.request import urlopen
    from urllib.error import HTTPError
except ImportError:  # Python 2
    from urllib2 import urlopen
    from urllib2 import HTTPError

# Identifiants de règles réservés à secauto (hors plage ZAP officielle)
PLUGIN_ENV_FILE = "990001"       # CWE-200 : fichier .env exposé
PLUGIN_GIT_REPO = "990002"       # CWE-538 : dépôt .git accessible
PLUGIN_ACTUATOR = "990003"       # CWE-16  : Spring Boot Actuator ouvert
PLUGIN_STACKTRACE = "990004"     # CWE-209 : stack trace divulguée

_state = {"zap": None, "target": "", "findings": []}


# ---------------------------------------------------------------------------
# sondes HTTP
# ---------------------------------------------------------------------------
def _fetch(base_url, path):
    """Requête GET simple, renvoie (url, code, corps décodé)."""
    url = base_url.rstrip("/") + path
    try:
        res = urlopen(url, timeout=10)
        code, body = res.getcode(), res.read(200000)
    except HTTPError as err:
        code, body = err.code, err.read(200000)
    except Exception as exc:
        sys.stderr.write("secauto hook : sonde %s indisponible (%s)\n" % (path, exc))
        return url, 0, ""
    return url, code, body.decode("utf-8", "ignore")


def _finding(plugin_id, title, risk, cwe, url, evidence, description):
    """Enregistre un constat et tente de l'injecter dans les alertes ZAP."""
    item = {
        "tool": "zap",
        "category": "DAST",
        "title": title,
        "severity": risk,
        "rule_id": "ZAP-HOOK-" + plugin_id,
        "endpoint": "GET " + url,
        "evidence": evidence[:300],
        "cwe": [str(cwe)],
        "description": description,
        "pluginid": plugin_id,
    }
    _state["findings"].append(item)
    _raise_alert(item)


def _raise_alert(item):
    zap = _state.get("zap")
    if zap is None:
        return
    try:
        zap.alert.add(
            url=item["endpoint"],
            name=item["title"],
            riskId={"High": "3", "Medium": "2", "Low": "1"}.get(item["severity"], "1"),
            confidenceId="3",           # confiance forte (constat vérifié)
            description=item["description"],
            param="",
            attack=item["endpoint"],
            otherInfo="",
            evidence=item["evidence"],
            solution="Restreindre l'accès à la ressource ou supprimer le endpoint.",
            reference="https://owasp.org/www-project-top-ten/",
            cweId=item["cwe"][0],
            wascId="",
            messageId="",
        )
    except Exception as exc:  # API indisponible : le JSON écrit à la fin suffit
        sys.stderr.write("secauto hook : alert.add indisponible (%s)\n" % exc)


def _run_probes():
    base = _state["target"]
    if not base:
        return

    # 1. Fichier .env exposé (clés API, mots de passe, jetons)
    url, code, body = _fetch(base, "/.env")
    if code == 200 and len(body) > 10 and re.search(r"(?m)^[A-Z_][A-Z0-9_]*\s*=", body):
        _finding(
            PLUGIN_ENV_FILE,
            "SECAUTO - Exposed .env File",
            "Medium", 200, url,
            body.splitlines()[0][:120],
            "Un fichier .env contenant des variables d'environnement "
            "(secrets potentiels) est accessible publiquement sur %s." % url,
        )

    # 2. Dépôt .git accessible
    url, code, body = _fetch(base, "/.git/HEAD")
    if code == 200 and body.startswith("ref: refs/"):
        _finding(
            PLUGIN_GIT_REPO,
            "SECAUTO - Exposed Git Repository",
            "High", 538, url,
            body.strip()[:60],
            "Le répertoire .git du dépôt source est servi par le serveur web : "
            "le code source complet peut être reconstruit par un attaquant.",
        )

    # 3. Spring Boot Actuator ouvert (microservices type crAPI)
    url, code, body = _fetch(base, "/actuator")
    if code == 200 and body.strip().startswith("{") and '"_links"' in body:
        _finding(
            PLUGIN_ACTUATOR,
            "SECAUTO - Exposed Spring Boot Actuator",
            "Medium", 16, url,
            body[:200],
            "L'endpoint Actuator de Spring Boot est exposé sans "
            "authentification (inventaire des routes, santé, métriques).",
        )

    # 4. Stack trace divulguée sur une page d'erreur
    url, code, body = _fetch(base, "/secauto-probe-nonexistent-404")
    signature = None
    if "Traceback (most recent call last)" in body:
        signature = "Traceback (most recent call last)"
    elif re.search(r"java\.lang\.[A-Za-z]+Exception", body):
        signature = "java.lang.<*>Exception"
    elif re.search(r"(?m)^at [A-Za-z0-9_$.]+\([^)]*:\d+\)", body):
        signature = "at <class>.<method>(<file>:<line>)"
    if signature:
        _finding(
            PLUGIN_STACKTRACE,
            "SECAUTO - Stack Trace Disclosure",
            "Low", 209, url,
            signature,
            "La page d'erreur divulgue une stack trace (technologie et "
            "version exposées, aide à la préparation d'attaques ciblées).",
        )


def _write_results():
    """Écrit zap-custom.json dans le répertoire monté (/zap/wrk)."""
    if not _state["findings"]:
        return
    out = os.path.join("/zap/wrk", "zap-custom.json")
    try:
        with open(out, "w") as handle:
            json.dump({"findings": _state["findings"]}, handle, indent=2)
        sys.stderr.write("secauto hook : %d constat(s) -> %s\n"
                         % (len(_state["findings"]), out))
    except OSError as exc:
        sys.stderr.write("secauto hook : écriture zap-custom.json impossible (%s)\n" % exc)


# ---------------------------------------------------------------------------
# hooks appelés par zap-baseline.py
# ---------------------------------------------------------------------------
def cli_opts(opts):
    """Présent pour basculer zap-baseline.py hors du framework d'automatisation."""


def zap_started(zap, target):
    """ZAP est démarré et la cible accessible : lancer les sondes maison."""
    _state["zap"] = zap
    _state["target"] = target
    try:
        _run_probes()
    except Exception as exc:  # une sonde ne doit jamais casser le scan
        sys.stderr.write("secauto hook : erreur inattendue (%s)\n" % exc)


def pre_exit(fail_count, warn_count, pass_count):
    """Fin du scan : archiver les constats maison dans /zap/wrk."""
    _write_results()

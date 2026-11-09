#!/usr/bin/env python3
"""Détecteur complémentaire : BOLA / BFLA sur une API authentifiée.

Crée deux comptes de test, collecte un identifiant d'objet pour chacun, puis
vérifie si le jeton du premier permet d'accéder à l'objet du second (BOLA)
et si un utilisateur standard atteint un endpoint administratif (BFLA).

Tout est piloté par un fichier YAML : voir config/idor-crapi.yaml.

Utilisable seul :
    python3 scanners/custom/idor_probe.py --config config/idor-crapi.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any

import yaml


def http(method: str, url: str, body: Any = None, token: str | None = None, timeout: int = 20):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "User-Agent": "secauto-idor/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", "replace")
            return response.status, text
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"API injoignable : {url} ({exc})")


def as_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def dig(payload: Any, path: str | None, fallback_keys: list[str]) -> Any:
    if path:
        current = payload
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current
    if isinstance(payload, dict):
        for key in fallback_keys:
            if key in payload:
                return payload[key]
    return None


def signature(status: int, text: str) -> dict[str, Any]:
    return {"status": status, "bytes": len(text), "preview": text[:200]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    with open(args.config, encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    base = config["base_url"].rstrip("/")
    users_cfg = config.get("users", {})
    password = users_cfg.get("password", "SecAuto!2026")
    email_pattern = users_cfg.get("email_pattern", "secauto{n}@example.com")
    count = int(users_cfg.get("count", 2))

    sessions: list[dict[str, Any]] = []
    notes: list[str] = []
    findings: list[dict[str, Any]] = []

    # 1. Création + authentification des comptes de test
    for index in range(1, count + 1):
        email = email_pattern.format(n=index)
        signup = config.get("signup") or {}
        if signup.get("path"):
            body = json.loads(
                json.dumps(signup.get("body", {}))
                .replace("{email}", email)
                .replace("{password}", password)
                .replace("{n}", str(index))
            )
            status, text = http(signup.get("method", "POST"), base + signup["path"], body)
            if status >= 400 and status not in (409, 422):
                notes.append(f"inscription {email} : HTTP {status} — {text[:120]}")

        login = config.get("login") or {}
        if not login.get("path"):
            notes.append("bloc 'login' absent de la configuration")
            break
        body = json.loads(
            json.dumps(login.get("body", {}))
            .replace("{email}", email)
            .replace("{password}", password)
        )
        status, text = http(login.get("method", "POST"), base + login["path"], body)
        token = dig(as_json(text), login.get("token_path"),
                    ["token", "access_token", "accessToken", "jwt"])
        if status >= 400 or not token:
            notes.append(f"connexion {email} : HTTP {status} — jeton introuvable")
            continue
        sessions.append({"email": email, "token": token})

    if len(sessions) < 2:
        notes.append("moins de deux sessions valides : tests BOLA impossibles")
        json.dump({"findings": findings, "notes": notes}, sys.stdout, indent=2, ensure_ascii=False)
        return 0

    # 2. Collecte d'un identifiant d'objet par utilisateur
    collect = config.get("collect") or {}
    access = config.get("access") or {}
    for session in sessions:
        status, text = http(collect.get("method", "GET"), base + collect["path"],
                            token=session["token"])
        payload = as_json(text)
        items = dig(payload, collect.get("items_path"), collect.get("items_keys", ["items", "data"]))
        if items is None and isinstance(payload, list):
            items = payload
        ids = []
        for item in items or []:
            if isinstance(item, dict) and collect.get("id_field") in item:
                ids.append(str(item[collect["id_field"]]))
            elif isinstance(item, (str, int)):
                ids.append(str(item))
        session["ids"] = ids
        session["collect"] = signature(status, text)
        if not ids:
            notes.append(f"{session['email']} : aucun objet collecté (HTTP {status})")

    # 3. BOLA : le jeton d'un utilisateur accède-t-il aux objets d'un autre ?
    for attacker in sessions:
        for victim in sessions:
            if attacker is victim or not victim.get("ids"):
                continue
            own_ok = True
            if attacker.get("ids"):
                own_status, _ = http(access.get("method", "GET"),
                                     base + access["path"].format(id=attacker["ids"][0]),
                                     token=attacker["token"])
                own_ok = 200 <= own_status < 300
            if not own_ok:
                continue
            for object_id in victim["ids"]:
                endpoint = base + access["path"].format(id=object_id)
                status, text = http(access.get("method", "GET"), endpoint,
                                    token=attacker["token"])
                leaked = status in range(200, 300) and object_id in text
                if leaked:
                    findings.append({
                        "title": "BOLA — accès à l'objet d'un autre utilisateur",
                        "severity": "high",
                        "description": (
                            f"Le jeton de {attacker['email']} permet de lire l'objet "
                            f"{object_id} appartenant à {victim['email']}. "
                            "L'API ne vérifie pas la propriété de l'objet (OWASP API1:2023)."
                        ),
                        "cwe": ["CWE-639"],
                        "owasp": ["API1:2023"],
                        "endpoint": f"{access.get('method', 'GET')} {access['path'].format(id=object_id)}",
                        "evidence": f"HTTP {status} — objet {object_id} retourné",
                        "rule_id": "custom.bola.cross-user-read",
                    })
                    break

    # 4. BFLA : un utilisateur standard atteint-il une fonction d'administration ?
    admin = config.get("admin") or {}
    if admin.get("enabled") and admin.get("path"):
        status, text = http(admin.get("method", "GET"), base + admin["path"],
                            token=sessions[0]["token"])
        payload = as_json(text)
        denied_markers = ("unauthorized", "forbidden", "access denied", "not allowed")
        denied = any(marker in text.lower() for marker in denied_markers)
        if 200 <= status < 300 and not denied and (payload not in (None, {}, [])):
            findings.append({
                "title": "BFLA — endpoint administratif accessible à un utilisateur standard",
                "severity": "high",
                "description": (
                    f"{sessions[0]['email']} (rôle standard) obtient une réponse exploitable "
                    f"sur {admin['path']}. Le contrôle d'autorisation au niveau fonction "
                    "est absent ou insuffisant (OWASP API5:2023)."
                ),
                "cwe": ["CWE-285"],
                "owasp": ["API5:2023"],
                "endpoint": f"{admin.get('method', 'GET')} {admin['path']}",
                "evidence": f"HTTP {status} — {len(text)} octets",
                "rule_id": "custom.bfla.admin-endpoint",
            })

    json.dump({"findings": findings, "notes": notes}, sys.stdout, indent=2, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

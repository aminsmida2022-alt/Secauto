#!/usr/bin/env python3
"""Détecteur complémentaire : BOLA / BFLA sur une API authentifiée.

Crée des comptes de test, collecte des identifiants d'objets exposés par
l'application, puis vérifie :
  - BOLA : le jeton d'un utilisateur standard permet-il de lire un objet
    appartenant à un autre utilisateur ?
  - BFLA : une fonction d'administration est-elle acceptée pour un compte
    standard ?

Tout est piloté par un fichier YAML : voir config/idor-crapi.yaml.

Utilisable seul :
    python3 scanners/custom/idor_probe.py --config config/idor-crapi.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
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


def http_multipart(url: str, token: str, field: str, filename: str,
                   content_type: str, content: str, method: str = "POST",
                   timeout: int = 30):
    """Envoi multipart/form-data minimal (création d'un objet de test)."""
    boundary = f"----secauto{uuid.uuid4().hex}"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
        f"{content}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Accept": "application/json",
        "User-Agent": "secauto-idor/0.1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
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


def extract_ids(payload: Any, block: dict[str, Any]) -> list[str]:
    items = dig(payload, block.get("items_path"), block.get("items_keys", ["items", "data"]))
    if items is None and isinstance(payload, list):
        items = payload
    ids: list[str] = []
    for item in items or []:
        if isinstance(item, dict):
            value = dig(item, block.get("id_path"),
                       [block["id_field"]] if block.get("id_field") else [])
            if value is not None:
                ids.append(str(value))
        elif isinstance(item, (str, int)):
            ids.append(str(item))
    return ids


def collect_ids(base: str, block: dict[str, Any], token: str) -> tuple[int, str, list[str]]:
    status, text = http(block.get("method", "GET"), base + block["path"], token=token)
    return status, text, extract_ids(as_json(text), block)


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
        suffix = f"{int(time.time()) % 10**6:06d}{index}"
        phone = "06" + suffix[-8:]
        signup = config.get("signup") or {}
        if signup.get("path"):
            body = json.loads(
                json.dumps(signup.get("body", {}))
                .replace("{email}", email)
                .replace("{password}", password)
                .replace("{phone}", phone)
                .replace("{n}", str(index))
            )
            status, text = http(signup.get("method", "POST"), base + signup["path"], body)
            already = "already registered" in text.lower()
            if status >= 400 and status not in (409, 422) and not already:
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

    # 2. Collecte des identifiants d'objets
    collect = config.get("collect") or {}
    access = config.get("access") or {}
    mode = str(collect.get("mode", "own"))
    candidate_ids: list[str] = []

    if mode == "others":
        # Les identifiants proviennent d'objets exposés par l'application et
        # appartenant à d'autres utilisateurs (forum, flux public, etc.).
        for session in sessions:
            status, text, ids = collect_ids(base, collect, session["token"])
            session["collect"] = signature(status, text)
            own_ids: set[str] = set()
            own_block = collect.get("own") or {}
            if own_block.get("path"):
                _, _, owned = collect_ids(base, own_block, session["token"])
                own_ids = set(owned)
            session["own_ids"] = own_ids
            session["ids"] = sorted(own_ids)
            if not ids:
                notes.append(f"{session['email']} : aucun identifiant exposé collecté (HTTP {status})")
            candidate_ids.extend(i for i in ids if i not in own_ids)
        candidate_ids = list(dict.fromkeys(candidate_ids))
        if not candidate_ids:
            notes.append("aucun identifiant d'objet exploitable pour le test BOLA")

        # Contrôle anti-faux-positif : l'endpoint doit refuser l'accès anonyme.
        if candidate_ids and access.get("require_auth"):
            anon_status, _ = http(access.get("method", "GET"),
                                  base + access["path"].format(id=candidate_ids[0]))
            if 200 <= anon_status < 300:
                notes.append(
                    f"accès anonyme accepté sur {access['path']} (HTTP {anon_status}) : "
                    "problème d'authentification, pas de BOLA — test ignoré"
                )
                candidate_ids = []
    else:
        # Mode "own" : chaque utilisateur possède ses objets, on croise les jetons.
        for session in sessions:
            status, text, ids = collect_ids(base, collect, session["token"])
            session["ids"] = ids
            session["own_ids"] = set(ids)
            session["collect"] = signature(status, text)
            if not ids:
                notes.append(f"{session['email']} : aucun objet collecté (HTTP {status})")

    # 3. BOLA : le jeton d'un utilisateur accède-t-il aux objets d'un autre ?
    reported_objects: set[str] = set()
    bola_hits: list[dict[str, Any]] = []
    for attacker in sessions:
        targets: list[str] = []
        if mode == "others":
            targets = [i for i in candidate_ids if i not in attacker["own_ids"]]
        else:
            for victim in sessions:
                if victim is not attacker:
                    targets.extend(i for i in victim.get("ids", []) if i not in attacker["own_ids"])
        for object_id in targets:
            if object_id in reported_objects:
                continue
            endpoint = base + access["path"].format(id=object_id)
            status, text = http(access.get("method", "GET"), endpoint, token=attacker["token"])
            payload = as_json(text)
            leak_keys = [k for k in access.get("leak_keys", [])
                         if isinstance(payload, dict) and k in payload]
            leaked = 200 <= status < 300 and (object_id in text or bool(leak_keys))
            if not leaked:
                continue
            reported_objects.add(object_id)
            bola_hits.append({
                "attacker": attacker["email"],
                "object_id": object_id,
                "status": status,
                "leak_keys": leak_keys,
            })

    if bola_hits:
        first = bola_hits[0]
        objects = [h["object_id"] for h in bola_hits]
        leak_union = sorted({k for h in bola_hits for k in h["leak_keys"]})
        evidence = f"HTTP {first['status']} — {len(objects)} objet(s) d'autres utilisateurs lisibles"
        evidence += f" (ex. {', '.join(objects[:3])})"
        if leak_union:
            evidence += f" ; champs : {', '.join(leak_union)}"
        findings.append({
            "title": "BOLA — accès aux objets d'autres utilisateurs",
            "severity": "high",
            "description": (
                f"Le jeton de {first['attacker']} permet de lire {len(objects)} objet(s) "
                "appartenant à d'autres utilisateurs (identifiants exposés publiquement "
                "par l'application). L'API ne vérifie pas la propriété de l'objet "
                "(OWASP API1:2023)."
            ),
            "cwe": ["CWE-639"],
            "owasp": ["API1:2023"],
            "endpoint": f"{access.get('method', 'GET')} {access['path'].format(id=objects[0])}",
            "evidence": evidence,
            "rule_id": "custom.bola.cross-user-read",
        })

    # 4. BFLA : un utilisateur standard peut-il exécuter une fonction d'administration ?
    admin = config.get("admin") or {}
    if admin.get("enabled") and admin.get("path"):
        setup = admin.get("setup") or {}
        setup_id = None
        setup_status = None
        if setup.get("path"):
            multipart = setup.get("multipart")
            if multipart:
                setup_status, setup_text = http_multipart(
                    base + setup["path"], sessions[0]["token"],
                    multipart.get("field", "file"),
                    multipart.get("filename", "secauto.mp4"),
                    multipart.get("content_type", "video/mp4"),
                    multipart.get("content", "secauto probe video"),
                    setup.get("method", "POST"),
                )
            else:
                setup_status, setup_text = http(setup.get("method", "POST"),
                                                base + setup["path"],
                                                token=sessions[0]["token"])
            setup_id = dig(as_json(setup_text), setup.get("id_path"), ["id"])
            if setup_id is None:
                notes.append(f"BFLA : préparation de l'objet impossible (HTTP {setup_status})")

        if setup_id is None:
            notes.append("BFLA : aucun identifiant d'objet de test — test ignoré")
        else:
            control = admin.get("control") or {}
            control_denied = None
            if control.get("path"):
                control_status, control_text = http(
                    control.get("method", "DELETE"),
                    base + control["path"].replace("{id}", str(setup_id)),
                    token=sessions[0]["token"],
                )
                markers = [m.lower() for m in control.get("denied_markers", [])]
                control_denied = control_status in (401, 403) or any(
                    m in control_text.lower() for m in markers
                )

            path = admin["path"].replace("{id}", str(setup_id))
            status, text = http(admin.get("method", "DELETE"), base + path,
                                token=sessions[0]["token"])
            payload = as_json(text)
            denied_markers = ("unauthorized", "forbidden", "access denied", "not allowed")
            denied = any(marker in text.lower() for marker in denied_markers)
            success_markers = [m.lower() for m in admin.get("success_markers", [])]
            if success_markers:
                succeeded = any(m in text.lower() for m in success_markers)
            else:
                succeeded = payload not in (None, {}, []) and "error" not in text.lower()
            if 200 <= status < 300 and not denied and succeeded:
                evidence = f"HTTP {status} sur la fonction admin avec un compte standard"
                if control_denied:
                    evidence += " ; la route standard refuse l'opération"
                findings.append({
                    "title": "BFLA — fonction d'administration accessible à un utilisateur standard",
                    "severity": "high",
                    "description": (
                        f"{sessions[0]['email']} (rôle standard) exécute avec succès la "
                        f"fonction d'administration {admin['path']} sur l'objet {setup_id}. "
                        "Le contrôle d'autorisation au niveau fonction est absent "
                        "(OWASP API5:2023)."
                    ),
                    "cwe": ["CWE-285"],
                    "owasp": ["API5:2023"],
                    "endpoint": f"{admin.get('method', 'DELETE')} {path}",
                    "evidence": evidence,
                    "rule_id": "custom.bfla.admin-endpoint",
                })

    json.dump({"findings": findings, "notes": notes}, sys.stdout, indent=2, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

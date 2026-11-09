#!/usr/bin/env python3
"""Détecteur complémentaire : robustesse des jetons JWT.

Vérifie trois choses sur un jeton réellement émis par l'application :
  1. la signature est-elle réellement contrôlée côté serveur ?
  2. le jeton porte-t-il une date d'expiration ?
  3. expose-t-il des données sensibles dans son payload (base64 non chiffré) ?

Utilisable seul :
    python3 scanners/custom/check_jwt.py --config config/idor-crapi.yaml
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
from typing import Any

import yaml


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def http(method: str, url: str, body: Any = None, token: str | None = None, timeout: int = 20):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "User-Agent": "secauto-jwt/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"API injoignable : {url} ({exc})")


def finding(title, severity, description, cwe, endpoint, evidence, rule_id):
    return {
        "title": title, "severity": severity, "description": description,
        "cwe": [cwe], "endpoint": endpoint, "evidence": evidence, "rule_id": rule_id,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    with open(args.config, encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    login = config.get("login") or {}
    protected = config.get("protected") or {}
    base = config["base_url"].rstrip("/")
    user = config.get("users", {}).get("email_pattern", "secauto1@example.com").format(n=1)
    password = config.get("users", {}).get("password", "SecAuto!2026")

    body = json.loads(
        json.dumps(login.get("body", {})).replace("{email}", user).replace("{password}", password)
    )
    status, text = http(login.get("method", "POST"), base + login["path"], body)
    payload = json.loads(text) if text.startswith("{") else {}
    token = payload.get("token") or payload.get("access_token")
    if not token:
        print(json.dumps({"findings": [], "notes": [f"aucun jeton obtenu (HTTP {status})"]}, indent=2))
        return 0

    findings = []
    parts = token.split(".")
    header: dict[str, Any] = {}
    claims: dict[str, Any] = {}
    if len(parts) == 3:
        try:
            header = json.loads(b64url_decode(parts[0]))
            claims = json.loads(b64url_decode(parts[1]))
        except Exception:  # noqa: BLE001
            findings.append(finding(
                "JWT non décodable", "info", "Le jeton n'est pas un JWT standard.",
                "CWE-345", f"POST {login['path']}", token[:60], "jwt.malformed",
            ))

    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        findings.append(finding(
            "JWT signé avec alg=none", "critical",
            "L'algorithme « none » accepte un jeton non signé : forgeage trivial.",
            "CWE-347", f"POST {login['path']}", f"alg={header.get('alg')}", "jwt.alg-none",
        ))

    if "exp" not in claims:
        findings.append(finding(
            "JWT sans date d'expiration", "medium",
            "Le jeton n'expire jamais : un vol de jeton reste exploitable indéfiniment.",
            "CWE-613", f"POST {login['path']}", f"claims={sorted(claims)}", "jwt.no-exp",
        ))

    sensitive = {"password", "pwd", "secret", "api_key", "apikey", "ssn", "credit_card"}
    leaked = sensitive & {str(k).lower() for k in claims}
    if leaked:
        findings.append(finding(
            "Données sensibles dans le payload JWT", "high",
            "Le payload JWT est seulement encodé en base64, pas chiffré.",
            "CWE-522", f"POST {login['path']}", f"champs={sorted(leaked)}", "jwt.sensitive-claims",
        ))

    # Test de non-vérification de signature : on altère le dernier caractère.
    if protected.get("path") and len(parts) == 3:
        tampered = ".".join(parts[:2] + [parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")])
        url = base + protected["path"]
        original_status, original_text = http(protected.get("method", "GET"), url, token=token)
        tampered_status, tampered_text = http(protected.get("method", "GET"), url, token=tampered)
        accepted = (
            200 <= original_status < 300
            and 200 <= tampered_status < 300
            and tampered_text.strip() == original_text.strip()
        )
        if accepted:
            findings.append(finding(
                "Signature JWT non vérifiée", "critical",
                "Un jeton dont la signature a été modifiée est accepté par le serveur : "
                "n'importe quel utilisateur peut forger un jeton (élévation de privilèges).",
                "CWE-347",
                f"{protected.get('method', 'GET')} {protected['path']}",
                f"HTTP {original_status} avec jeton valide, HTTP {tampered_status} avec signature altérée",
                "jwt.signature-not-verified",
            ))
        elif 200 <= original_status < 300:
            findings.append(finding(
                "Signature JWT contrôlée", "info",
                "Le jeton altéré est rejeté : la signature est bien vérifiée.",
                "CWE-347", f"{protected.get('method', 'GET')} {protected['path']}",
                f"HTTP {tampered_status} après altération", "jwt.signature-verified",
            ))

    json.dump({"findings": findings, "notes": []}, sys.stdout, indent=2, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

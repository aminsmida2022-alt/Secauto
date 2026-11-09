#!/usr/bin/env python3
"""Détecteur complémentaire : en-têtes de sécurité, cookies et CORS.

Sortie JSON sur stdout, consommable par secauto (catégorie CUSTOM).
Utilisable seul :
    python3 scanners/custom/check_headers.py --url http://localhost:3000
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

REQUIRED_HEADERS = {
    "content-security-policy": (
        "Content-Security-Policy absent : pas de défense en profondeur contre le XSS.",
        "CWE-693",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options absent : MIME sniffing possible.",
        "CWE-693",
    ),
    "referrer-policy": (
        "Referrer-Policy absent : fuite d'URL possible vers des tiers.",
        "CWE-200",
    ),
    "permissions-policy": (
        "Permissions-Policy absent : fonctionnalités navigateur non restreintes.",
        "CWE-693",
    ),
}

INSECURE_COOKIE_ATTRS = {
    "httponly": ("Cookie sans HttpOnly : accessible via document.cookie en cas de XSS.", "CWE-1004"),
    "secure": ("Cookie sans Secure : peut transiter en clair.", "CWE-614"),
    "samesite": ("Cookie sans SameSite : exposé au CSRF.", "CWE-1275"),
}


def finding(title, severity, description, cwe, endpoint, evidence="", rule_id=""):
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "cwe": [cwe] if cwe else [],
        "endpoint": endpoint,
        "evidence": evidence,
        "rule_id": rule_id,
    }


def fetch(url: str, timeout: int = 15):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(url, headers={"User-Agent": "secauto-headers/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.status, response.headers, response.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, b""
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"injoignable : {url} ({exc})")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()

    url = args.url.rstrip("/")
    status, headers, _ = fetch(url + "/")
    lower = {k.lower(): v for k, v in headers.items()}
    findings = []

    for name, (message, cwe) in REQUIRED_HEADERS.items():
        if name not in lower:
            findings.append(
                finding(
                    f"En-tête de sécurité manquant : {name}",
                    "low",
                    message,
                    cwe,
                    f"GET {url}/",
                    rule_id=f"headers.missing.{name}",
                )
            )

    if "x-frame-options" not in lower and "frame-ancestors" not in lower.get(
        "content-security-policy", ""
    ):
        findings.append(
            finding(
                "Protection anti-clickjacking absente",
                "medium",
                "Ni X-Frame-Options ni CSP frame-ancestors : l'application peut être "
                "embarquée dans une iframe malveillante.",
                "CWE-1021",
                f"GET {url}/",
                rule_id="headers.missing.x-frame-options",
            )
        )

    if url.startswith("https://") and "strict-transport-security" not in lower:
        findings.append(
            finding(
                "HSTS absent",
                "low",
                "Strict-Transport-Security absent : downgrade HTTP possible.",
                "CWE-319",
                f"GET {url}/",
                rule_id="headers.missing.hsts",
            )
        )

    for disclosed in ("server", "x-powered-by", "x-aspnet-version"):
        if disclosed in lower:
            findings.append(
                finding(
                    f"Divulgation de technologie via {disclosed}",
                    "info",
                    "L'en-tête révèle la pile technique et facilite le ciblage.",
                    "CWE-200",
                    f"GET {url}/",
                    evidence=f"{disclosed}: {lower[disclosed]}",
                    rule_id=f"headers.disclosure.{disclosed}",
                )
            )

    allow_origin = lower.get("access-control-allow-origin", "")
    allow_credentials = lower.get("access-control-allow-credentials", "").lower() == "true"
    if allow_origin == "*":
        findings.append(
            finding(
                "CORS permissif : origine joker",
                "high" if allow_credentials else "medium",
                "Access-Control-Allow-Origin: * "
                + ("avec credentials=True est une configuration critique."
                   if allow_credentials else "autorise toute origine à lire les réponses."),
                "CWE-942",
                f"GET {url}/",
                evidence=f"ACAO={allow_origin}, ACAC={allow_credentials}",
                rule_id="cors.wildcard",
            )
        )
    elif allow_origin and "localhost" not in url and allow_origin != url:
        findings.append(
            finding(
                "CORS : origine externe autorisée",
                "medium",
                "Une origine tierce est explicitement autorisée à lire les réponses.",
                "CWE-942",
                f"GET {url}/",
                evidence=f"ACAO={allow_origin}",
                rule_id="cors.external-origin",
            )
        )

    for raw_cookie in headers.get_all("Set-Cookie") or []:
        name = raw_cookie.split("=", 1)[0].strip()
        attributes = raw_cookie.lower()
        for attribute, (message, cwe) in INSECURE_COOKIE_ATTRS.items():
            if attribute not in attributes:
                findings.append(
                    finding(
                        f"Cookie « {name} » sans attribut {attribute.capitalize()}",
                        "medium" if attribute in ("httponly", "samesite") else "low",
                        message,
                        cwe,
                        f"GET {url}/",
                        evidence=raw_cookie[:160],
                        rule_id=f"cookie.missing.{attribute}",
                    )
                )

    json.dump({"status": status, "findings": findings}, sys.stdout, indent=2, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Exécution des outils SAST / DAST / SCA / CUSTOM.

Chaque runner :
  - vérifie que l'outil est disponible ;
  - écrit sa sortie brute dans <run_dir>/raw/ ;
  - renvoie une liste de Finding normalisés.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .model import Finding, normalize_cwe, normalize_owasp

ROOT = Path(__file__).resolve().parent.parent


class RunnerError(RuntimeError):
    """Erreur d'exécution d'un outil (binaire absent, sortie illisible...)."""


class Runner:
    name = "base"
    category = "SAST"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.options = options or {}

    def available(self) -> bool:
        return True

    def missing_hint(self) -> str:
        return ""

    def run(self, target_name: str, target: dict, run_dir: Path) -> list[Finding]:
        raise NotImplementedError

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _raw_dir(run_dir: Path) -> Path:
        raw = run_dir / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        return raw

    @staticmethod
    def _exec(cmd: list[str], cwd: Path | None = None, timeout: int = 1800) -> subprocess.CompletedProcess:
        # Sortie redirigée vers des fichiers plutôt que des tubes : certains
        # outils (npm) lancent des sous-processus qui héritent du tube et
        # empêchent la lecture d'atteindre l'EOF.
        import tempfile

        try:
            with tempfile.TemporaryFile(mode="w+") as out, tempfile.TemporaryFile(mode="w+") as err:
                process = subprocess.run(
                    cmd,
                    cwd=str(cwd) if cwd else None,
                    stdout=out,
                    stderr=err,
                    text=True,
                    timeout=timeout,
                    stdin=subprocess.DEVNULL,
                )
                out.seek(0)
                err.seek(0)
                return subprocess.CompletedProcess(cmd, process.returncode, out.read(), err.read())
        except FileNotFoundError as exc:  # pragma: no cover
            raise RunnerError(f"binaire introuvable : {cmd[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise RunnerError(f"délai dépassé ({timeout}s) pour {cmd[0]}") from exc


# ---------------------------------------------------------------------------
# SAST — Semgrep
# ---------------------------------------------------------------------------
class SemgrepRunner(Runner):
    name = "semgrep"
    category = "SAST"

    def available(self) -> bool:
        return shutil.which("semgrep") is not None

    def missing_hint(self) -> str:
        return "pipx install semgrep   (ou : uv tool install semgrep)"

    def run(self, target_name: str, target: dict, run_dir: Path) -> list[Finding]:
        source = ROOT / target.get("source", "")
        if not source.exists():
            print(f"   [!] semgrep : source absente ({source}) — ignoré")
            return []

        raw = self._raw_dir(run_dir) / "semgrep.json"
        cmd = ["semgrep", "scan", "--quiet", "--metrics=off", "--json", "--output", str(raw)]
        cmd += ["--config", str(ROOT / "scanners" / "semgrep" / "rules")]
        if not self.options.get("offline"):
            cmd += ["--config", "p/owasp-top-ten", "--config", "p/javascript"]
        for pattern in (target.get("sast") or {}).get("exclude", []):
            cmd += ["--exclude", pattern]
        cmd.append(str(source))

        result = self._exec(cmd, timeout=2400)
        if not raw.exists():
            raise RunnerError(
                "semgrep n'a produit aucun rapport. stderr: "
                + (result.stderr or "")[:500]
            )

        payload = json.loads(raw.read_text(encoding="utf-8"))
        findings: list[Finding] = []
        for item in payload.get("results", []):
            extra = item.get("extra", {}) or {}
            metadata = extra.get("metadata", {}) or {}
            path = item.get("path", "")
            try:
                path = str(Path(path).resolve().relative_to(ROOT))
            except Exception:
                pass
            line = (item.get("start") or {}).get("line")
            check_id = item.get("check_id", "")
            findings.append(
                Finding(
                    tool=self.name,
                    category=self.category,
                    target=target_name,
                    title=metadata.get("title") or check_id.split(".")[-1].replace("-", " "),
                    severity=extra.get("severity", "info"),
                    description=(extra.get("message") or "").strip(),
                    cwe=metadata.get("cwe"),
                    owasp=metadata.get("owasp"),
                    rule_id=check_id,
                    file=path,
                    line=line,
                    endpoint=f"{path}:{line}" if line else path,
                    evidence=(extra.get("lines") or "").strip()[:500],
                    raw_ref=f"raw/semgrep.json#results/{len(findings)}",
                )
            )
        print(f"   [+] semgrep : {len(findings)} résultat(s)")
        return findings


# ---------------------------------------------------------------------------
# SCA — Trivy
# ---------------------------------------------------------------------------
class TrivyRunner(Runner):
    name = "trivy"
    category = "SCA"

    def available(self) -> bool:
        return shutil.which("trivy") is not None

    def missing_hint(self) -> str:
        return "https://trivy.dev/latest/getting-started/installation/"

    def run(self, target_name: str, target: dict, run_dir: Path) -> list[Finding]:
        source = ROOT / target.get("source", "")
        if not source.exists():
            print(f"   [!] trivy : source absente ({source}) — ignoré")
            return []

        raw = self._raw_dir(run_dir) / "trivy.json"
        # SCA = dépendances vulnérables + secrets. Les mauvaises configurations
        # IaC (charts, manifestes k8s) sont hors périmètre du cours et sont
        # couvertes par le détecteur d'en-têtes côté application.
        cmd = [
            "trivy", "fs", "--quiet",
            "--format", "json",
            "--output", str(raw),
            "--scanners", "vuln,secret",
            str(source),
        ]
        if self.options.get("offline"):
            cmd.insert(2, "--offline-scan")
        result = self._exec(cmd, timeout=2400)
        if not raw.exists():
            raise RunnerError("trivy n'a produit aucun rapport. stderr: " + (result.stderr or "")[:500])

        payload = json.loads(raw.read_text(encoding="utf-8"))
        findings: list[Finding] = []
        for block in payload.get("Results", []):
            artifact = block.get("Target", "")
            for vuln in block.get("Vulnerabilities") or []:
                findings.append(
                    Finding(
                        tool=self.name,
                        category="SCA",
                        target=target_name,
                        title=f"{vuln.get('PkgName', '?')} — {vuln.get('VulnerabilityID', '?')}",
                        severity=vuln.get("Severity", "info"),
                        description=(vuln.get("Title") or vuln.get("Description") or "")[:1000],
                        cwe=vuln.get("CweIDs"),
                        rule_id=vuln.get("VulnerabilityID", ""),
                        file=artifact,
                        evidence=f"{vuln.get('PkgName')} {vuln.get('InstalledVersion')} → {vuln.get('FixedVersion') or 'pas de correctif'}",
                        raw_ref=f"raw/trivy.json#{artifact}",
                    )
                )
            for secret in block.get("Secrets") or []:
                findings.append(
                    Finding(
                        tool=self.name,
                        category="SCA",
                        target=target_name,
                        title=secret.get("Title") or "Secret détecté",
                        severity=secret.get("Severity", "high"),
                        description=secret.get("Match", "")[:500],
                        cwe=["CWE-798"],
                        rule_id=secret.get("RuleID", ""),
                        file=artifact,
                        line=secret.get("StartLine"),
                        evidence=secret.get("Match", "")[:200],
                        raw_ref=f"raw/trivy.json#{artifact}",
                    )
                )
            for misconf in block.get("Misconfigurations") or []:
                findings.append(
                    Finding(
                        tool=self.name,
                        category="SCA",
                        target=target_name,
                        title=misconf.get("Title") or misconf.get("ID", "Mauvaise configuration"),
                        severity=misconf.get("Severity", "info"),
                        description=(misconf.get("Description") or "")[:1000],
                        rule_id=misconf.get("AVDID") or misconf.get("ID", ""),
                        file=artifact,
                        evidence=(misconf.get("Message") or "")[:300],
                        raw_ref=f"raw/trivy.json#{artifact}",
                    )
                )
        print(f"   [+] trivy : {len(findings)} résultat(s)")
        return findings


# ---------------------------------------------------------------------------
# SCA — npm audit
# ---------------------------------------------------------------------------
class NpmAuditRunner(Runner):
    name = "npm-audit"
    category = "SCA"

    def available(self) -> bool:
        return shutil.which("npm") is not None

    def missing_hint(self) -> str:
        return "installer Node.js (npm)"

    def run(self, target_name: str, target: dict, run_dir: Path) -> list[Finding]:
        source = ROOT / target.get("source", "")
        if not (source / "package.json").exists():
            print(f"   [!] npm audit : pas de package.json dans {source} — ignoré")
            return []

        raw = self._raw_dir(run_dir) / "npm-audit.json"
        result = self._exec(["npm", "audit", "--json"], cwd=source, timeout=300)
        text = result.stdout.strip() or "{}"
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            raise RunnerError("sortie npm audit illisible (projet sans lockfile ?)")
        raw.write_text(text, encoding="utf-8")

        findings: list[Finding] = []
        for pkg, data in (payload.get("vulnerabilities") or {}).items():
            vias = data.get("via") or []
            advisories = [v for v in vias if isinstance(v, dict)]
            if not advisories:
                reasons = ", ".join(v for v in vias if isinstance(v, str)) or "dépendance transitive"
                findings.append(
                    Finding(
                        tool=self.name,
                        category="SCA",
                        target=target_name,
                        title=f"{pkg} — vulnérabilité transitive",
                        severity=data.get("severity", "info"),
                        description=reasons,
                        rule_id=pkg,
                        file=str(source / "package.json"),
                        evidence=f"plage vulnérable : {data.get('range', '?')}",
                        raw_ref=f"raw/npm-audit.json#vulnerabilities/{pkg}",
                    )
                )
                continue
            for adv in advisories:
                findings.append(
                    Finding(
                        tool=self.name,
                        category="SCA",
                        target=target_name,
                        title=adv.get("title") or f"{pkg} — avis de sécurité",
                        severity=adv.get("severity") or data.get("severity", "info"),
                        description=(adv.get("title") or "")[:1000],
                        cwe=adv.get("cwe"),
                        rule_id=adv.get("source") or adv.get("url", pkg),
                        file=str(source / "package.json"),
                        evidence=f"{pkg} {data.get('range', '?')} → {adv.get('url', '')}",
                        raw_ref=f"raw/npm-audit.json#vulnerabilities/{pkg}",
                    )
                )
        print(f"   [+] npm audit : {len(findings)} résultat(s)")
        return findings


# ---------------------------------------------------------------------------
# SAST — SonarQube (via API Web)
# ---------------------------------------------------------------------------
class SonarRunner(Runner):
    name = "sonarqube"
    category = "SAST"

    def available(self) -> bool:
        return bool(os.environ.get("SONAR_HOST_URL"))

    def missing_hint(self) -> str:
        return "exporter SONAR_HOST_URL et SONAR_TOKEN (ou SONAR_TOKEN vide si anonyme)"

    def run(self, target_name: str, target: dict, run_dir: Path) -> list[Finding]:
        import urllib.parse
        import urllib.request

        host = os.environ["SONAR_HOST_URL"].rstrip("/")
        token = os.environ.get("SONAR_TOKEN", "")
        project = target.get("sonar_key") or target_name
        query = urllib.parse.urlencode(
            {"componentKeys": project, "resolved": "false", "ps": "500", "p": "1"}
        )
        request = urllib.request.Request(f"{host}/api/issues/search?{query}")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise RunnerError(f"appel API SonarQube impossible : {exc}") from exc

        raw = self._raw_dir(run_dir) / "sonarqube.json"
        raw.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        findings = []
        for issue in payload.get("issues", []):
            component = issue.get("component", "")
            findings.append(
                Finding(
                    tool=self.name,
                    category="SAST",
                    target=target_name,
                    title=issue.get("rule", "SonarQube issue"),
                    severity=issue.get("severity", "info"),
                    description=issue.get("message", ""),
                    cwe=issue.get("cwe"),
                    rule_id=issue.get("rule", ""),
                    file=component,
                    line=issue.get("line"),
                    endpoint=f"{component}:{issue.get('line', '')}",
                    raw_ref=f"raw/sonarqube.json#issues/{issue.get('key', '')}",
                )
            )
        print(f"   [+] sonarqube : {len(findings)} résultat(s)")
        return findings


# ---------------------------------------------------------------------------
# DAST — OWASP ZAP
# ---------------------------------------------------------------------------
class ZapRunner(Runner):
    name = "zap"
    category = "DAST"
    IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

    def available(self) -> bool:
        return shutil.which("docker") is not None

    def missing_hint(self) -> str:
        return "installer Docker (scripts/install-docker.sh)"

    def docker_cli(self) -> list[str]:
        """Utilise scripts/dk si présent (gère l'accès au groupe docker)."""
        wrapper = ROOT / "scripts" / "dk"
        return [str(wrapper)] if wrapper.exists() else ["docker"]

    def run(self, target_name: str, target: dict, run_dir: Path) -> list[Finding]:
        base_url = target.get("base_url", "")
        if not base_url:
            return []
        dast = target.get("dast", {}) or {}
        mode = dast.get("mode", "baseline")
        raw_dir = self._raw_dir(run_dir)
        script = {
            "baseline": "zap-baseline.py",
            "full": "zap-full-scan.py",
            "api": "zap-api-scan.py",
        }.get(mode, "zap-baseline.py")

        cmd = [
            *self.docker_cli(), "run", "--rm", "--network", "host",
            "-v", f"{raw_dir}:/zap/wrk:rw",
            "-t", self.IMAGE,
            script,
            "-J", "zap.json",
            "-r", "zap.html",
            "-w", "zap.md",
            "-I",  # ne pas échouer sur les warnings, on analyse le rapport
        ]
        if mode == "api":
            spec = dast.get("openapi") or ""
            if not spec:
                print("   [!] zap : mode api sans spec OpenAPI — bascule en baseline")
                script = "zap-baseline.py"
                cmd[cmd.index("zap-api-scan.py")] = script
                cmd += ["-t", base_url]
            else:
                cmd += ["-t", spec, "-f", "openapi"]
        else:
            cmd += ["-t", base_url, "-m", "3"]
            if dast.get("ajax_spider"):
                cmd += ["-j"]

        result = self._exec(cmd, timeout=3600)
        zap_json = raw_dir / "zap.json"
        if not zap_json.exists():
            raise RunnerError(
                "ZAP n'a produit aucun rapport (démarrage Docker ?). stderr: "
                + (result.stderr or "")[:500]
            )

        payload = json.loads(zap_json.read_text(encoding="utf-8"))
        findings: list[Finding] = []
        for site in payload.get("site", []):
            for alert in site.get("alerts", []):
                risk = str(alert.get("riskdesc", "")).split("(")[0].strip()
                cwe = [] if alert.get("cweid") in (None, "-1", -1, "0") else [alert["cweid"]]
                instances = alert.get("instances") or [{}]
                for instance in instances[:10]:
                    uri = instance.get("uri", site.get("@name", ""))
                    method = instance.get("method", "")
                    findings.append(
                        Finding(
                            tool=self.name,
                            category="DAST",
                            target=target_name,
                            title=alert.get("alert") or alert.get("name", "Alerte ZAP"),
                            severity=risk,
                            description=re.sub(r"<[^>]+>", "", alert.get("desc", ""))[:1500],
                            cwe=normalize_cwe(cwe),
                            rule_id=f"ZAP-{alert.get('pluginid', '')}",
                            endpoint=f"{method} {uri}".strip(),
                            evidence=(instance.get("evidence") or instance.get("param") or "")[:300],
                            raw_ref=f"raw/zap.json#plugin/{alert.get('pluginid', '')}",
                        )
                    )
        print(f"   [+] zap : {len(findings)} résultat(s)")
        return findings


# ---------------------------------------------------------------------------
# CUSTOM — détecteurs maison (scripts Python, sortie JSON)
# ---------------------------------------------------------------------------
class CustomRunner(Runner):
    name = "custom"
    category = "CUSTOM"

    def run(self, target_name: str, target: dict, run_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        raw_dir = self._raw_dir(run_dir)
        for detector in target.get("custom", []) or []:
            name = detector.get("name", "detector")
            script = ROOT / detector["script"]
            if not script.exists():
                print(f"   [!] custom:{name} : script absent ({script})")
                continue
            args = [
                str(a).format(base_url=target.get("base_url", ""), source=target.get("source", ""))
                for a in detector.get("args", [])
            ]
            env = dict(os.environ)
            env.setdefault("SECAUTO_TARGET", target_name)
            import tempfile

            with tempfile.TemporaryFile(mode="w+") as out, tempfile.TemporaryFile(mode="w+") as err:
                process = subprocess.run(
                    [sys.executable, str(script), *args],
                    stdout=out, stderr=err, text=True, timeout=600,
                    cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL,
                )
                out.seek(0)
                err.seek(0)
                stdout = out.read()
                stderr = err.read()
            result = subprocess.CompletedProcess(
                [sys.executable, str(script), *args], process.returncode, stdout, stderr
            )
            raw_path = raw_dir / f"custom-{name}.json"
            raw_path.write_text(result.stdout or "{}", encoding="utf-8")
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip().splitlines()
                reason = detail[0] if detail else "sortie vide"
                print(f"   [!] custom:{name} : échec — {reason}")
                continue
            try:
                payload = json.loads(result.stdout or "{}")
            except json.JSONDecodeError:
                print(f"   [!] custom:{name} : sortie non JSON")
                continue
            items = payload.get("findings", payload) if isinstance(payload, dict) else payload
            for item in items or []:
                findings.append(
                    Finding(
                        tool=f"custom:{name}",
                        category="CUSTOM",
                        target=target_name,
                        title=item.get("title", name),
                        severity=item.get("severity", "info"),
                        description=item.get("description", ""),
                        cwe=item.get("cwe"),
                        owasp=item.get("owasp"),
                        rule_id=item.get("rule_id", name),
                        endpoint=item.get("endpoint", ""),
                        evidence=str(item.get("evidence", ""))[:500],
                        raw_ref=f"raw/custom-{name}.json",
                    )
                )
            print(f"   [+] custom:{name} : {len(items or [])} résultat(s)")
        return findings


RUNNERS: dict[str, type[Runner]] = {
    "sast": SemgrepRunner,
    "sca": TrivyRunner,
    "sca-npm": NpmAuditRunner,
    "sonar": SonarRunner,
    "dast": ZapRunner,
    "custom": CustomRunner,
}


def build_runner(tool: str, options: dict[str, Any] | None = None) -> Runner | None:
    cls = RUNNERS.get(tool)
    return cls(options) if cls else None

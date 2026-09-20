"""Wrapper sobre wpscan: escáner de WordPress. Solo se lanza si whatweb detectó WordPress."""

import json
import subprocess


def scan(url: str) -> list[dict]:
    result = subprocess.run(
        ["wpscan", "--url", url, "--no-banner", "--random-user-agent", "-f", "json"],
        capture_output=True,
        text=True,
        check=True,
    )

    data = json.loads(result.stdout) if result.stdout.strip() else {}

    findings = []
    version = data.get("version") or {}
    if version.get("number"):
        findings.append({"tipo": "Versión WordPress", "detalle": version["number"]})

    for finding in data.get("interesting_findings", []) or []:
        findings.append({"tipo": finding.get("type", "?"), "detalle": finding.get("to_s", "")})

    for plugin_name in (data.get("plugins") or {}).keys():
        findings.append({"tipo": "Plugin", "detalle": plugin_name})

    return findings

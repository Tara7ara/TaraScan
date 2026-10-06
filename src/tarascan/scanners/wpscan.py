"""Wrapper sobre wpscan: escáner de WordPress. Solo se lanza si whatweb detectó WordPress."""

import json
import subprocess


def scan(url: str) -> list[dict]:
    result = subprocess.run(
        ["wpscan", "--url", url, "--no-banner", "--random-user-agent", "-f", "json"],
        capture_output=True,
        text=True,
        timeout=180,
    )

    raw = result.stdout.strip()
    if not raw:
        if result.returncode != 0:
            result.check_returncode()
        return []

    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end <= start:
        return []

    try:
        data = json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        return []

    findings = []
    version = data.get("version") or {}
    if version.get("number"):
        findings.append({"tipo": "Versión WordPress", "detalle": version["number"]})

    for finding in data.get("interesting_findings", []) or []:
        findings.append({"tipo": finding.get("type", "?"), "detalle": finding.get("to_s", "")})

    for plugin_name in (data.get("plugins") or {}).keys():
        findings.append({"tipo": "Plugin", "detalle": plugin_name})

    return findings

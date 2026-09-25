"""Wrapper sobre nuclei: escáner de vulnerabilidades por plantillas.

Se excluye la severidad 'info' para no ahogar la salida en detecciones triviales;
recon centrado en lo que importa (low/medium/high/critical).
"""

import json
import subprocess


def scan(url: str) -> list[dict]:
    result = subprocess.run(
        [
            "nuclei",
            "-u", url,
            "-jsonl",
            "-silent",
            "-severity", "low,medium,high,critical",
            "-omit-raw",
            "-disable-update-check",
            "-no-color",
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = data.get("info", {})
        findings.append(
            {
                "template": data.get("template-id", ""),
                "severity": info.get("severity", ""),
                "name": info.get("name", ""),
                "matched": data.get("matched-at", data.get("host", "")),
            }
        )

    # Ordena por severidad (critical primero) para leer lo grave de un vistazo.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return findings

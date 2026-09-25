"""Wrapper sobre feroxbuster: descubrimiento de contenido web recursivo.

Herramienta más pesada que gobuster (recorre subdirectorios), por eso se lanza
solo bajo el flag --deep, no en la cadena por defecto.
"""

import json
import subprocess

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"


def scan(url: str, wordlist: str = DEFAULT_WORDLIST, depth: int = 2) -> list[dict]:
    result = subprocess.run(
        [
            "feroxbuster",
            "-u", url,
            "-w", wordlist,
            "--depth", str(depth),
            "--silent",
            "--json",
            "--no-state",
        ],
        capture_output=True,
        text=True,
        timeout=900,
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
        if data.get("type") != "response":
            continue
        findings.append(
            {
                "path": data.get("url", data.get("path", "")),
                "status": str(data.get("status", "")),
            }
        )

    return findings

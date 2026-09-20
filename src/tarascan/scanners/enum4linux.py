"""Wrapper sobre enum4linux: enumeración SMB/AD básica (SO, shares, usuarios).

Salida de texto plano heredada sin formato estable entre versiones, así que
en vez de parsear secciones concretas nos quedamos con las líneas que
aportan información real, descartando separadores y líneas vacías.
"""

import subprocess

_SKIP_PREFIXES = ("=", "Starting enum4linux", "enum4linux complete")


def scan(target: str) -> list[str]:
    result = subprocess.run(
        ["enum4linux", "-o", "-U", "-S", target],
        capture_output=True,
        text=True,
        check=True,
    )

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(_SKIP_PREFIXES):
            continue
        findings.append(line)

    return findings

"""Wrapper sobre enum4linux: enumeración SMB/AD básica (SO, shares, usuarios).

Salida de texto plano heredada sin formato estable entre versiones, así que
en vez de parsear secciones concretas nos quedamos con las líneas que
aportan información real, descartando separadores y líneas vacías.
"""

import re
import subprocess

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SKIP_PREFIXES = ("=", "Starting enum4linux", "enum4linux complete")


def scan(target: str) -> list[str]:
    result = subprocess.run(
        ["enum4linux", "-o", "-U", "-S", target],
        capture_output=True,
        text=True,
        check=True,
    )

    findings = []
    for raw_line in result.stdout.splitlines():
        line = _ANSI_RE.sub("", raw_line).strip()
        if not line or line.startswith(_SKIP_PREFIXES):
            continue
        findings.append(line)

    return findings

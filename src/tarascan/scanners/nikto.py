"""Wrapper sobre nikto: escáner de vulnerabilidades/configuración web básicas."""

import subprocess

_SKIP_PREFIXES = (
    "Target IP",
    "Target Hostname",
    "Target Port",
    "Platform",
    "Start Time",
    "Server:",
    "End Time",
    "requests:",
)

_MISSING_HEADER_MARK = "Suggested security header missing: "


def scan(url: str) -> list[str]:
    result = subprocess.run(
        ["nikto", "-h", url, "-nointeractive"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=True,
    )

    findings = []
    missing_headers = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        line = line[2:]
        if line.startswith(_SKIP_PREFIXES) or "host(s) tested" in line or "requests:" in line:
            continue
        if _MISSING_HEADER_MARK in line:
            missing_headers.append(line.split(_MISSING_HEADER_MARK, 1)[1].split(".", 1)[0])
            continue
        findings.append(line)

    if missing_headers:
        findings.insert(0, f"{len(missing_headers)} cabeceras de seguridad recomendadas ausentes: {', '.join(missing_headers)}")

    return findings

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


def scan(url: str) -> list[str]:
    result = subprocess.run(
        ["nikto", "-h", url, "-nointeractive"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=True,
    )

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        line = line[2:]
        if line.startswith(_SKIP_PREFIXES) or "host(s) tested" in line or "requests:" in line:
            continue
        findings.append(line)

    return findings

"""Wrapper sobre subfinder: enumeración pasiva de subdominios (OSINT, no toca el objetivo)."""

import subprocess


def scan(domain: str) -> list[str]:
    result = subprocess.run(
        ["subfinder", "-d", domain, "-silent", "-disable-update-check"],
        capture_output=True,
        text=True,
        timeout=120,
    )

    subs = sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})
    return subs

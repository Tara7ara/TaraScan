"""Wrapper sobre searchsploit (exploit-db): busca exploits conocidos para un servicio/versión."""

import json
import subprocess


def scan(term: str) -> list[dict]:
    result = subprocess.run(
        ["searchsploit", "--json", term],
        capture_output=True,
        text=True,
        check=True,
    )

    if not result.stdout.strip():
        return []

    data = json.loads(result.stdout)
    findings = []
    for exploit in data.get("RESULTS_EXPLOIT", []):
        findings.append(
            {
                "title": exploit.get("Title", "").strip(),
                "type": exploit.get("Type", "").strip(),
                "edb": exploit.get("EDB-ID", "").strip(),
            }
        )

    return findings

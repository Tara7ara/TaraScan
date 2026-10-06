"""Wrapper sobre searchsploit (exploit-db): busca exploits conocidos para un servicio/versión."""

import json
import subprocess


def scan(term: str) -> list[dict]:
    result = subprocess.run(
        ["searchsploit", "--json", term],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )

    raw = result.stdout.strip()
    if not raw:
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
    for exploit in data.get("RESULTS_EXPLOIT", []):
        findings.append(
            {
                "title": exploit.get("Title", "").strip(),
                "type": exploit.get("Type", "").strip(),
                "edb": exploit.get("EDB-ID", "").strip(),
            }
        )

    return findings

"""Wrapper sobre whatweb: fingerprinting de tecnologías web."""

import json
import subprocess


def scan(url: str) -> dict:
    result = subprocess.run(
        ["whatweb", "-q", "--log-json=/dev/stdout", url],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )

    entries = json.loads(result.stdout) if result.stdout.strip() else []
    entry = entries[0] if entries else {}

    findings = {}
    for name, info in entry.get("plugins", {}).items():
        values = info.get("string") or info.get("version") or info.get("module")
        if isinstance(values, str):
            findings[name] = values
        elif isinstance(values, (list, tuple)):
            findings[name] = ", ".join(str(v) for v in values)
        elif values:
            findings[name] = str(values)
        else:
            findings[name] = "detectado"

    return {"status": entry.get("http_status"), "plugins": findings}

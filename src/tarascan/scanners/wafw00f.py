"""Wrapper sobre wafw00f: detección de WAF/IPS delante de una web."""

import json
import subprocess


def scan(url: str) -> dict:
    empty = {"detected": False, "firewall": "", "manufacturer": ""}
    result = subprocess.run(
        ["wafw00f", "-a", "-f", "json", "-o", "-", url],
        capture_output=True,
        text=True,
        timeout=60,
    )

    raw = result.stdout.strip()
    if not raw:
        return empty

    start = raw.find("[")
    end = raw.rfind("]")
    if start == -1 or end <= start:
        return empty

    try:
        data = json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        return empty
    entry = data[0] if isinstance(data, list) and data else {}
    detected = bool(entry.get("detected"))
    firewall = entry.get("firewall", "") if detected else ""
    manufacturer = entry.get("manufacturer", "") if detected else ""

    return {
        "detected": detected,
        "firewall": firewall,
        "manufacturer": manufacturer,
    }

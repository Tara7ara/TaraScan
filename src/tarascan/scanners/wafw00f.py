"""Wrapper sobre wafw00f: detección de WAF/IPS delante de una web.

Útil para interpretar 403/redirecciones raras: si hay WAF, muchos "hallazgos"
de gobuster/ffuf pueden ser falsos positivos del propio WAF.
"""

import json
import subprocess


def scan(url: str) -> dict:
    result = subprocess.run(
        ["wafw00f", "-a", "-f", "json", "-o", "-", url],
        capture_output=True,
        text=True,
        check=True,
    )

    if not result.stdout.strip():
        return {"detected": False, "firewall": ""}

    data = json.loads(result.stdout)
    entry = data[0] if isinstance(data, list) and data else {}
    detected = bool(entry.get("detected"))
    firewall = entry.get("firewall", "") if detected else ""
    manufacturer = entry.get("manufacturer", "") if detected else ""

    return {
        "detected": detected,
        "firewall": firewall,
        "manufacturer": manufacturer,
    }

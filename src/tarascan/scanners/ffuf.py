"""Wrapper sobre ffuf: fuzzing de archivos sensibles/backups habituales (distinto de gobuster,
que enumera directorios con una wordlist genérica)."""

import json
import subprocess
import tempfile
import uuid
from pathlib import Path

COMMON_FILES = [
    ".env",
    ".git/config",
    "backup.zip",
    "backup.tar.gz",
    "config.php.bak",
    "db.sql",
    "site.zip",
    "wp-config.php.bak",
]

def scan(base_url: str) -> list[dict]:
    calibration = f"tarascan-cal-{uuid.uuid4().hex}.zzz"
    url = base_url.rstrip("/") + "/FUZZ"
    wordlist = "\n".join([calibration, *COMMON_FILES])

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out_file:
        out_path = Path(out_file.name)

    data = {}
    try:
        subprocess.run(
            ["ffuf", "-u", url, "-w", "-", "-mc", "200,301,302,403", "-of", "json", "-o", str(out_path), "-s"],
            input=wordlist,
            capture_output=True,
            text=True,
            check=True,
            timeout=180,
        )
        if out_path.is_file():
            content = out_path.read_text(encoding="utf-8").strip()
            if content:
                data = json.loads(content)
    finally:
        out_path.unlink(missing_ok=True)

    results = data.get("results", [])
    # Huella del comodín: cómo respondió el servidor a la sonda inexistente.
    wildcard = None
    for r in results:
        if r.get("input", {}).get("FUZZ") == calibration:
            wildcard = (r.get("status"), r.get("length"))
            break

    findings = []
    for r in results:
        name = r.get("input", {}).get("FUZZ")
        if not name or name == calibration:
            continue
        # Si el servidor es comodín, descartamos lo que responda igual que la sonda.
        if wildcard is not None and (r.get("status"), r.get("length")) == wildcard:
            continue
        findings.append({"path": f"/{name}", "status": str(r["status"]), "size": str(r["length"])})

    return findings

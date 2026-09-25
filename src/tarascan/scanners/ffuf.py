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

# Nombre que casi seguro no existe: sirve de sonda de comodín. Si el servidor lo
# devuelve como "encontrado" (proxy/WordPress que responde igual a todo), su
# status+tamaño es la huella del comodín y se filtran los resultados iguales.
_CALIBRATION = f"tarascan-cal-{uuid.uuid4().hex}.zzz"


def scan(base_url: str) -> list[dict]:
    url = base_url.rstrip("/") + "/FUZZ"
    wordlist = "\n".join([_CALIBRATION, *COMMON_FILES])

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out_file:
        out_path = Path(out_file.name)

    try:
        subprocess.run(
            ["ffuf", "-u", url, "-w", "-", "-mc", "200,301,302,403", "-of", "json", "-o", str(out_path), "-s"],
            input=wordlist,
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(out_path.read_text())
    finally:
        out_path.unlink(missing_ok=True)

    results = data.get("results", [])
    # Huella del comodín: cómo respondió el servidor a la sonda inexistente.
    wildcard = None
    for r in results:
        if r["input"]["FUZZ"] == _CALIBRATION:
            wildcard = (r["status"], r["length"])
            break

    findings = []
    for r in results:
        name = r["input"]["FUZZ"]
        if name == _CALIBRATION:
            continue
        # Si el servidor es comodín, descartamos lo que responda igual que la sonda.
        if wildcard is not None and (r["status"], r["length"]) == wildcard:
            continue
        findings.append({"path": f"/{name}", "status": str(r["status"]), "size": str(r["length"])})

    return findings

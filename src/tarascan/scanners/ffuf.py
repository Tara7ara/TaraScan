"""Wrapper sobre ffuf: fuzzing de archivos sensibles/backups habituales (distinto de gobuster,
que enumera directorios con una wordlist genérica)."""

import json
import subprocess
import tempfile
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
    url = base_url.rstrip("/") + "/FUZZ"
    wordlist = "\n".join(COMMON_FILES)

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

    return [
        {"path": f"/{r['input']['FUZZ']}", "status": str(r["status"]), "size": str(r["length"])}
        for r in data.get("results", [])
    ]

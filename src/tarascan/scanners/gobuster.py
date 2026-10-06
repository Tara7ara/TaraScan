"""Wrapper sobre gobuster: fuerza bruta de directorios web con una wordlist."""

import os
import subprocess

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
_FALLBACK_WORDLISTS = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
)

# Solo nos interesan los status que de verdad indican algo (encontrado,
# redirigido o bloqueado). 400/5xx suelen ser ruido del backend/proxy, no
# hallazgos reales — se excluyen pidiéndoselo directamente a gobuster con -s.
_STATUS_CODES = "200,204,301,302,307,401,403"


def _get_wordlist(preferred: str) -> str:
    if os.path.exists(preferred):
        return preferred
    for fb in _FALLBACK_WORDLISTS:
        if os.path.exists(fb):
            return fb
    return preferred


def scan(target: str, wordlist: str = DEFAULT_WORDLIST) -> list[dict]:
    url = target if target.startswith("http") else f"http://{target}"
    wl = _get_wordlist(wordlist)
    result = subprocess.run(
        ["gobuster", "dir", "-k", "-u", url, "-w", wl, "-q", "--no-error", "-b", "", "-s", _STATUS_CODES],
        capture_output=True,
        text=True,
        check=True,
        timeout=180,
    )

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        path, _, rest = line.partition(" ")
        status = ""
        if "(Status:" in rest:
            status = rest.split("(Status:", 1)[1].split(")", 1)[0].strip()
        findings.append({"path": path if path.startswith("/") else f"/{path}", "status": status})

    return findings

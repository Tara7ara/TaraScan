"""Wrapper sobre gobuster: fuerza bruta de directorios web con una wordlist."""

import subprocess

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"


def scan(target: str, wordlist: str = DEFAULT_WORDLIST) -> list[dict]:
    url = target if target.startswith("http") else f"http://{target}"
    result = subprocess.run(
        ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-error"],
        capture_output=True,
        text=True,
        check=True,
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

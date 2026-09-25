"""Wrapper sobre sqlmap: prueba de inyección SQL sobre una URL.

Herramienta intrusiva — solo se lanza a petición explícita (flag --sqli), nunca
en la cadena automática.
"""

import subprocess


def scan(url: str) -> list[str]:
    # --batch responde con los valores por defecto (sin preguntas interactivas);
    # --crawl=1 sigue un nivel de enlaces para encontrar parámetros que probar.
    result = subprocess.run(
        [
            "sqlmap",
            "-u", url,
            "--batch",
            "--crawl=1",
            "--level=1",
            "--risk=1",
            "--flush-session",
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )

    findings = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        low = line.lower()
        if "is vulnerable" in low or "sqlmap identified" in low or low.startswith("parameter:"):
            findings.append(line)

    return findings

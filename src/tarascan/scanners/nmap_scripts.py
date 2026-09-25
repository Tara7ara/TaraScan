"""Scripts NSE de nmap: pasa los scripts 'default' y 'vuln and safe' sobre los puertos ya abiertos.

Se limita a la categoría 'safe' de vuln para no lanzar comprobaciones intrusivas
o que puedan tumbar el servicio — recon, no explotación. Se excluye 'vulners'
a propósito: vuelca cientos de CVEs por servicio (ruido) y se solapa con la
información que ya da searchsploit.
"""

import subprocess

_SCRIPTS = "default,(vuln and safe) and not vulners"


def scan(target: str, ports: list[str]) -> dict:
    if not ports:
        return {}

    result = subprocess.run(
        ["nmap", "-Pn", "-sV", "-p", ",".join(ports), "--script", _SCRIPTS, "-oN", "-", target],
        capture_output=True,
        text=True,
        check=True,
    )

    findings: dict[str, list[str]] = {}
    current = "host"
    for raw in result.stdout.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        # Cabecera de un puerto: "22/tcp open ssh ..."
        if "/tcp" in stripped and (" open" in stripped or " filtered" in stripped) and not stripped.startswith("|"):
            current = stripped.split()[0]
            continue
        # Líneas de salida de un script NSE: empiezan por "|" o "|_".
        if stripped.startswith("|"):
            text = stripped.lstrip("|_").strip()
            if text:
                findings.setdefault(current, []).append(text)

    return {k: v for k, v in findings.items() if v}

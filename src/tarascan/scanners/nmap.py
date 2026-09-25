"""Wrapper sobre nmap: lanza un escaneo rápido con detección de versión y devuelve los puertos abiertos ya parseados."""

import subprocess


def scan(target: str) -> list[dict]:
    # -sV añade detección de versión: da nombres de servicio más fiables y,
    # sobre todo, la versión concreta (7.º campo del formato grepable) que
    # luego alimenta a searchsploit.
    result = subprocess.run(
        ["nmap", "-F", "-sV", "-oG", "-", target],
        capture_output=True,
        text=True,
        check=True,
    )

    ports = []
    for line in result.stdout.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        ports_field = line.split("Ports:", 1)[1].split("\t")[0].strip()
        for entry in ports_field.split(", "):
            fields = entry.split("/")
            if len(fields) < 5:
                continue
            port, state, proto, _owner, service = fields[:5]
            if state != "open":
                continue
            # Con -sV el formato grepable añade rpc_info (índice 5) y version (índice 6).
            version = fields[6].strip() if len(fields) > 6 else ""
            ports.append(
                {
                    "port": port,
                    "proto": proto,
                    "service": service or "?",
                    "version": version,
                }
            )

    return ports

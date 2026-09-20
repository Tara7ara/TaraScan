"""Wrapper sobre nmap: lanza un escaneo rápido y devuelve los puertos abiertos ya parseados."""

import subprocess


def scan(target: str) -> list[dict]:
    result = subprocess.run(
        ["nmap", "-F", "-oG", "-", target],
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
            ports.append({"port": port, "proto": proto, "service": service or "?"})

    return ports

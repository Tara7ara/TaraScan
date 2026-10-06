"""Wrapper sobre nbtscan: nombres NetBIOS (137/udp) del objetivo."""

import socket
import subprocess


def scan(target: str) -> list[dict]:
    # nbtscan peta con hostnames (sale con error 2), así que resolvemos a IP primero.
    try:
        ip = socket.gethostbyname(target)
    except OSError:
        ip = target

    result = subprocess.run(
        ["nbtscan", ip],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0 and not result.stdout.strip():
        return []

    hosts = []
    seen_separator = False
    for line in result.stdout.splitlines():
        # Las filas van tras la línea de guiones de la cabecera.
        if set(line.strip()) == {"-"}:
            seen_separator = True
            continue
        if not seen_separator or not line.strip():
            continue
        # "IP  NetBIOS-Name  Server  User  MAC" separado por espacios múltiples.
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        mac = parts[-1] if ":" in parts[-1] else ""
        name = parts[1]
        hosts.append({"ip": ip, "name": name, "mac": mac})

    return hosts

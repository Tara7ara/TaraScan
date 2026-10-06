"""Wrapper sobre onesixtyone: fuerza bruta de comunidades SNMP (161/udp)."""

import os
import re
import socket
import subprocess

# Diccionario de comunidades de seclists; si no está, lo lanzamos sin -c y que
# onesixtyone tire de su comunidad por defecto.
_COMMUNITY_FILE = "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt"
_LINE = re.compile(r"^(\S+)\s+\[(.+?)\]\s*(.*)$")


def scan(target: str) -> list[dict]:
    # onesixtyone solo traga IP/CIDR: si nos pasan un dominio, lo resolvemos antes.
    try:
        ip = socket.gethostbyname(target)
    except OSError:
        ip = target

    cmd = ["onesixtyone"]
    if os.path.exists(_COMMUNITY_FILE):
        cmd += ["-c", _COMMUNITY_FILE, ip]
    else:
        cmd += [ip]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    found = []
    seen = set()
    for line in result.stdout.splitlines():
        match = _LINE.match(line.strip())
        if match:
            community = match.group(2)
            # onesixtyone puede repetir la misma comunidad (varias respuestas);
            # nos quedamos con la primera de cada una.
            if community in seen:
                continue
            seen.add(community)
            found.append({"community": community, "info": match.group(3).strip()})

    return found

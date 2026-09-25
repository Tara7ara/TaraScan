"""Wrapper sobre onesixtyone: fuerza bruta de comunidades SNMP (161/udp)."""

import os
import re
import subprocess

# Lista de comunidades habituales de seclists; si no está, se cae a public/private.
_COMMUNITY_FILE = "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt"
_LINE = re.compile(r"^(\S+)\s+\[(.+?)\]\s*(.*)$")


def scan(target: str) -> list[dict]:
    cmd = ["onesixtyone"]
    if os.path.exists(_COMMUNITY_FILE):
        cmd += ["-c", _COMMUNITY_FILE, target]
    else:
        cmd += [target, "public", target, "private"]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    found = []
    for line in result.stdout.splitlines():
        match = _LINE.match(line.strip())
        if match:
            found.append({"community": match.group(2), "info": match.group(3).strip()})

    return found

"""Wrapper sobre smbclient: listado de recursos SMB compartidos, sin autenticación."""

import subprocess

_TYPES = ("Disk", "IPC", "Printer")


def scan(target: str) -> list[dict]:
    result = subprocess.run(
        ["smbclient", "-L", f"//{target}", "-N", "-g"],
        capture_output=True,
        text=True,
        check=True,
    )

    shares = []
    for line in result.stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) >= 2 and parts[0] in _TYPES:
            shares.append(
                {
                    "type": parts[0],
                    "name": parts[1],
                    "comment": parts[2] if len(parts) > 2 else "",
                }
            )

    return shares

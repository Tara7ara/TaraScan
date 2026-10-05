"""Wrapper sobre hydra: fuerza bruta de credenciales contra un servicio."""

import subprocess

DEFAULT_USERS = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
DEFAULT_PASSWORDS = "/usr/share/seclists/Passwords/Common-Credentials/best110.txt"


def scan(
    target: str,
    service: str,
    users: str = DEFAULT_USERS,
    passwords: str = DEFAULT_PASSWORDS,
) -> list[dict]:
    # -f para al primer login válido; -o - no existe en hydra, así que
    # parseamos el stdout normal (líneas "[puerto][servicio] host: ...").
    result = subprocess.run(
        ["hydra", "-L", users, "-P", passwords, "-f", "-t", "4", f"{service}://{target}"],
        capture_output=True,
        text=True,
        timeout=900,
    )

    creds = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if "login:" in line and "password:" in line:
            login = line.split("login:", 1)[1].split("password:", 1)[0].strip()
            password = line.split("password:", 1)[1].strip()
            creds.append({"login": login, "password": password})

    return creds

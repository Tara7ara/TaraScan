"""Wrapper sobre netexec (nxc): enumeración SMB — info del host y recursos con sesión nula."""

import re
import subprocess

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# nxc antepone a cada línea el prefijo de log entre corchetes: [*], [+], [-].
_PREFIX = re.compile(r"^\[[*+\-]\]\s*")


def scan(target: str) -> dict:
    # -u '' -p '' fuerza el intento de sesión nula (anónima); --shares lista
    # los recursos si el servidor lo permite sin autenticación.
    result = subprocess.run(
        ["nxc", "smb", target, "-u", "", "-p", "", "--shares"],
        capture_output=True,
        text=True,
        timeout=120,
    )

    host_info: list[str] = []
    shares: list[str] = []
    parsed_any = False
    for raw in (result.stdout + result.stderr).splitlines():
        # nxc mete bytes nulos en algunos campos (dominio, línea de null-auth).
        line = _ANSI.sub("", raw).replace("\x00", "").strip()
        if not line.startswith("SMB"):
            continue
        parsed_any = True
        # Quita el "SMB  <ip>  <puerto>  <host>" de cabecera y deja el mensaje.
        parts = line.split(None, 4)
        message = _PREFIX.sub("", parts[4]).strip() if len(parts) > 4 else ""
        if not message:
            continue
        marker = parts[4].lstrip()[:3]
        if marker.startswith("[*]") or marker.startswith("[+]"):
            # Ruido de nxc: la línea "\:" del null-auth y el label "Enumerated shares".
            if message in ("\\:", "Enumerated shares") or set(message) <= {"\\", ":"}:
                continue
            host_info.append(message)
        else:
            # Salta la cabecera de la tabla de shares y la fila de guiones.
            if ("Permissions" in message and "Remark" in message) or set(message) <= {"-", " "}:
                continue
            shares.append(message)

    # Si nxc no devolvió ninguna línea SMB y salió con error, no lo ocultamos:
    # normalmente significa que nxc está roto (incompatibilidad de impacket) o
    # que no pudo hablar con el objetivo. Se propaga para que el CLI lo reporte.
    if not parsed_any and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise subprocess.CalledProcessError(
            result.returncode, "nxc", output=result.stdout,
            stderr=detail[-1] if detail else "nxc no devolvió salida",
        )

    return {"host": host_info, "shares": shares}

"""Wrapper sobre enum4linux: enumeración SMB/AD básica (SO, shares, usuarios).

Salida de texto plano heredada sin formato estable entre versiones. En vez de
intentar parsear cada campo, se agrupan las líneas bajo las secciones que el
propio enum4linux ya imprime (cabeceras tipo "===( Users on X )==="), con
nombres en español, descartando el ruido conocido (avisos del smbclient local
sin relación con el objetivo, líneas vacías, el preámbulo repetitivo).
"""

import re
import subprocess

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SECTION_HEADER_RE = re.compile(r"^=+\(\s*(.+?)\s*\)=+$")
_NOISE_LINES = ("Can't load /etc/samba/smb.conf - run testparm to debug it",)
_USER_LINE_RE = re.compile(r"^user:\[(.+)\]\s+rid:\[(.+)\]$")

# (prefijo del título de sección tal como lo imprime enum4linux -> sección en español)
# None como destino = sección conocida pero sin valor añadido, se descarta entera.
_SECTION_MAP = (
    ("Target Information", None),
    ("Enumerating Workgroup/Domain", "Dominio"),
    ("Session Check", "Acceso"),
    ("Getting domain SID", "Dominio"),
    ("OS information", "Sistema operativo"),
    ("Users on", "Usuarios"),
    ("Share Enumeration", "Recursos compartidos"),
)


def scan(target: str) -> dict[str, list[str]]:
    result = subprocess.run(
        ["enum4linux", "-o", "-U", "-S", target],
        capture_output=True,
        text=True,
        check=True,
    )

    sections: dict[str, list[str]] = {}
    current = None  # None = fuera de cualquier sección reconocida, se descarta

    for raw_line in result.stdout.splitlines():
        line = _ANSI_RE.sub("", raw_line).strip()
        if not line or line in _NOISE_LINES:
            continue

        header = _SECTION_HEADER_RE.match(line)
        if header:
            title = header.group(1)
            current = next((label for prefix, label in _SECTION_MAP if title.startswith(prefix)), None)
            continue

        if line.startswith(("Starting enum4linux", "enum4linux complete")):
            current = None
            continue

        if current is None:
            continue

        if current == "Usuarios":
            user_match = _USER_LINE_RE.match(line)
            if user_match:
                name, rid = user_match.groups()
                sections.setdefault(current, []).append(f"{name} (RID {rid})")
            continue

        sections.setdefault(current, []).append(line)

    if not sections:
        # Ninguna cabecera de sección conocida: puede ser otra versión de
        # enum4linux con un formato distinto. Mejor devolver todo en bruto
        # que dar la impresión de que no se encontró nada.
        for raw_line in result.stdout.splitlines():
            line = _ANSI_RE.sub("", raw_line).strip()
            if line and line not in _NOISE_LINES:
                sections.setdefault("Salida completa", []).append(line)

    return sections

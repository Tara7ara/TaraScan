"""Wrapper sobre nikto: escáner de vulnerabilidades/configuración web básicas."""

import subprocess

_SKIP_PREFIXES = (
    "Target IP",
    "Target Hostname",
    "Target Port",
    "Platform",
    "Start Time",
    "Server:",
    "End Time",
    "requests:",
)

_MISSING_HEADER_MARK = "Suggested security header missing: "
_NOISE_MARKS = ("No CGI Directories found",)

# Otros avisos de nikto que son la misma categoría (higiene de cabeceras) pero
# no usan el texto de _MISSING_HEADER_MARK: se funden en el mismo resumen en
# vez de repetir la misma idea dos veces con IDs de plugin distintos.
_EXTRA_HEADER_ISSUES = (
    ("X-Frame-Options header is deprecated", "x-frame-options"),
    ("The X-Content-Type-Options header is not set", "x-content-type-options"),
)


def scan(url: str) -> list[str]:
    result = subprocess.run(
        ["nikto", "-h", url, "-nointeractive"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=True,
    )

    findings = []
    missing_headers = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        line = line[2:]
        if line.startswith(_SKIP_PREFIXES) or "host(s) tested" in line or "requests:" in line:
            continue
        if any(mark in line for mark in _NOISE_MARKS):
            continue

        if _MISSING_HEADER_MARK in line:
            header = line.split(_MISSING_HEADER_MARK, 1)[1].split(".", 1)[0]
            if header not in missing_headers:
                missing_headers.append(header)
            continue

        extra = next((header for mark, header in _EXTRA_HEADER_ISSUES if mark in line), None)
        if extra:
            if extra not in missing_headers:
                missing_headers.append(extra)
            continue

        findings.append(line)

    if missing_headers:
        findings.insert(0, f"{len(missing_headers)} cabeceras de seguridad recomendadas ausentes: {', '.join(missing_headers)}")

    return findings

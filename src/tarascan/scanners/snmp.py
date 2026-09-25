"""Wrapper sobre snmpwalk: intenta enumerar por SNMP con la comunidad 'public' (161/udp).

nmap -F solo escanea TCP, así que SNMP (UDP) no aparece en la tabla de puertos;
por eso se prueba directamente con un timeout corto. Si no hay respuesta, se
descarta en silencio.
"""

import subprocess

# 'public' es la comunidad por defecto de facto; onesixtyone probaría más.
_COMMUNITY = "public"


def scan(target: str) -> list[str]:
    result = subprocess.run(
        ["snmpwalk", "-v2c", "-c", _COMMUNITY, "-t", "3", "-r", "1", target],
        capture_output=True,
        text=True,
        timeout=30,
    )

    output = result.stdout.strip()
    if not output or "No Response" in output or "Timeout" in output:
        return []

    # Cada línea es "OID = TIPO: valor"; nos quedamos con las que traen valor.
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if " = " in line and not line.endswith("= "):
            findings.append(line)

    return findings

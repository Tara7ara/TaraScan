"""Wrapper sobre snmpwalk: intenta enumerar por SNMP con la comunidad 'public' (161/udp)."""

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
    if not output:
        return []

    # Cada línea es "OID = TIPO: valor"; nos quedamos con las que traen valor.
    # OJO: NO se descarta todo por un "Timeout"/"No Response" suelto al final:
    # un walk puede cortar en un OID tras haber recogido datos válidos (típico
    # bajo carga), y esos datos siguen siendo buenos. Solo se ignoran las líneas
    # de error (no casan con "OID = TIPO: valor").
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if " = " in line and not line.endswith("= ") and "No Response" not in line and "Timeout" not in line:
            findings.append(line)

    return findings

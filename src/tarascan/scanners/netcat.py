"""Banner grabbing con nc: intenta capturar el banner de un puerto abierto."""

import subprocess


def grab(target: str, port: str, timeout: int = 5) -> str:
    # -w corta la conexión si el servicio no habla; enviamos una línea vacía
    # por stdin para empujar a servicios tipo HTTP a responder algo.
    try:
        result = subprocess.run(
            ["nc", "-w", str(timeout), target, port],
            input="\r\n",
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
    except subprocess.TimeoutExpired:
        return ""

    banner = (result.stdout or "").strip()
    # Nos quedamos con las primeras líneas útiles, sin volcar cuerpos enteros.
    lines = [line.strip() for line in banner.splitlines() if line.strip()]
    return " | ".join(lines[:4])

import argparse
import subprocess
import sys

from tarascan.scanners import nmap


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tarascan",
        description="Recon de un objetivo encadenando herramientas ya instaladas, salida unificada por terminal.",
    )
    parser.add_argument("target", help="dominio o IP a escanear")
    args = parser.parse_args()

    print(f"[tarascan] recon sobre {args.target}\n")

    print("== nmap (puertos abiertos) ==")
    try:
        ports = nmap.scan(args.target)
    except FileNotFoundError:
        print("nmap no está instalado o no está en el PATH", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"nmap falló: {exc}", file=sys.stderr)
        sys.exit(1)

    if not ports:
        print("  sin puertos abiertos en el escaneo rápido (-F)")
    else:
        for p in ports:
            print(f"  {p['port']}/{p['proto']}  {p['service']}")


if __name__ == "__main__":
    main()

import argparse
import subprocess
import sys

from rich.console import Console
from rich.table import Table

from tarascan.scanners import gobuster, nmap

console = Console()
error_console = Console(stderr=True, style="bold red")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tarascan",
        description="Recon de un objetivo encadenando herramientas ya instaladas, salida unificada por terminal.",
    )
    parser.add_argument("target", help="dominio o IP a escanear")
    args = parser.parse_args()

    console.rule(f"[bold]tarascan[/] · recon sobre [cyan]{args.target}[/]")

    try:
        ports = nmap.scan(args.target)
    except FileNotFoundError:
        error_console.print("nmap no está instalado o no está en el PATH")
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        error_console.print(f"nmap falló: {exc}")
        sys.exit(1)

    console.print("\n[bold]nmap[/] — puertos abiertos")
    if not ports:
        console.print("  [dim]sin puertos abiertos en el escaneo rápido (-F)[/]")
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Puerto")
        table.add_column("Proto")
        table.add_column("Servicio")
        for p in ports:
            table.add_row(p["port"], p["proto"], p["service"])
        console.print(table)

    web_ports = [p for p in ports if "http" in p["service"].lower()]
    if web_ports:
        port = web_ports[0]["port"]
        scheme = "https" if port in ("443", "8443") else "http"
        netloc = args.target if port in ("80", "443") else f"{args.target}:{port}"
        console.print("\n[bold]gobuster[/] — rutas encontradas")
        try:
            findings = gobuster.scan(f"{scheme}://{netloc}")
        except FileNotFoundError:
            error_console.print("gobuster no está instalado o no está en el PATH")
        except subprocess.CalledProcessError as exc:
            error_console.print(f"gobuster falló: {exc}")
        else:
            if not findings:
                console.print("  [dim]sin rutas encontradas con la wordlist por defecto[/]")
            else:
                gb_table = Table(show_header=True, header_style="bold")
                gb_table.add_column("Ruta")
                gb_table.add_column("Status")
                for f in findings:
                    gb_table.add_row(f["path"], f["status"])
                console.print(gb_table)


if __name__ == "__main__":
    main()

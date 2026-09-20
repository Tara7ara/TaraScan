import argparse
import subprocess
import sys

from rich.console import Console
from rich.table import Table

from tarascan.scanners import enum4linux, ffuf, gobuster, nikto, nmap, smbclient, whatweb, wpscan

console = Console()
error_console = Console(stderr=True, style="bold red")


def _run(tool: str, fn, *args):
    try:
        return fn(*args)
    except FileNotFoundError:
        error_console.print(f"{tool} no está instalado o no está en el PATH")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        message = f"{tool} falló (código {exc.returncode})"
        if detail:
            message += f":\n{detail[:500]}"
        error_console.print(message, markup=False, highlight=False)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tarascan",
        description="Recon de un objetivo encadenando herramientas ya instaladas, salida unificada por terminal.",
    )
    parser.add_argument("target", help="dominio o IP a escanear")
    args = parser.parse_args()

    console.rule(f"[bold]tarascan[/] · recon sobre [cyan]{args.target}[/]")

    ports = _run("nmap", nmap.scan, args.target)
    if ports is None:
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
        url = f"{scheme}://{netloc}"

        console.print("\n[bold]whatweb[/] — tecnologías detectadas")
        info = _run("whatweb", whatweb.scan, url)
        if info is not None:
            if not info["plugins"]:
                console.print("  [dim]sin resultados[/]")
            else:
                ww_table = Table(show_header=True, header_style="bold")
                ww_table.add_column("Plugin")
                ww_table.add_column("Detalle")
                for name, value in info["plugins"].items():
                    ww_table.add_row(name, value)
                console.print(ww_table)

        console.print("\n[bold]gobuster[/] — rutas encontradas")
        findings = _run("gobuster", gobuster.scan, url)
        if findings is not None:
            if not findings:
                console.print("  [dim]sin rutas encontradas con la wordlist por defecto[/]")
            else:
                gb_table = Table(show_header=True, header_style="bold")
                gb_table.add_column("Ruta")
                gb_table.add_column("Status")
                for f in findings:
                    gb_table.add_row(f["path"], f["status"])
                console.print(gb_table)

        console.print("\n[bold]ffuf[/] — archivos sensibles/backups")
        hits = _run("ffuf", ffuf.scan, url)
        if hits is not None:
            if not hits:
                console.print("  [dim]sin hallazgos entre los nombres habituales probados[/]")
            else:
                ff_table = Table(show_header=True, header_style="bold")
                ff_table.add_column("Ruta")
                ff_table.add_column("Status")
                ff_table.add_column("Tamaño")
                for h in hits:
                    ff_table.add_row(h["path"], h["status"], h["size"])
                console.print(ff_table)

        console.print("\n[bold]nikto[/] — configuración/vulnerabilidades web")
        nikto_findings = _run("nikto", nikto.scan, url)
        if nikto_findings is not None:
            if not nikto_findings:
                console.print("  [dim]sin hallazgos[/]")
            else:
                for finding in nikto_findings:
                    console.print(f"  - {finding}", markup=False, highlight=False)

        if info is not None and "WordPress" in info["plugins"]:
            console.print("\n[bold]wpscan[/] — WordPress detectado")
            wp_findings = _run("wpscan", wpscan.scan, url)
            if wp_findings is not None:
                if not wp_findings:
                    console.print("  [dim]sin hallazgos[/]")
                else:
                    wp_table = Table(show_header=True, header_style="bold")
                    wp_table.add_column("Tipo")
                    wp_table.add_column("Detalle")
                    for f in wp_findings:
                        wp_table.add_row(f["tipo"], f["detalle"])
                    console.print(wp_table)

    smb_ports = [p for p in ports if p["port"] in ("139", "445")]
    if smb_ports:
        console.print("\n[bold]smbclient[/] — recursos compartidos")
        shares = _run("smbclient", smbclient.scan, args.target)
        if shares is not None:
            if not shares:
                console.print("  [dim]sin recursos visibles sin autenticación[/]")
            else:
                sc_table = Table(show_header=True, header_style="bold")
                sc_table.add_column("Tipo")
                sc_table.add_column("Nombre")
                sc_table.add_column("Comentario")
                for s in shares:
                    sc_table.add_row(s["type"], s["name"], s["comment"])
                console.print(sc_table)

        console.print("\n[bold]enum4linux[/] — enumeración SMB")
        e4l_findings = _run("enum4linux", enum4linux.scan, args.target)
        if e4l_findings is not None:
            if not e4l_findings:
                console.print("  [dim]sin hallazgos[/]")
            else:
                for finding in e4l_findings:
                    console.print(f"  - {finding}", markup=False, highlight=False)


if __name__ == "__main__":
    main()

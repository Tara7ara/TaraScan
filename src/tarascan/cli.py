import argparse
import subprocess
import sys

from rich.console import Console
from rich.table import Table

from tarascan.scanners import enum4linux, ffuf, gobuster, nikto, nmap, smbclient, whatweb, wpscan

console = Console()
error_console = Console(stderr=True, style="bold red")


def _status_markup(status: str) -> str:
    try:
        code = int(status)
    except ValueError:
        return status
    color = "green" if code < 300 else "yellow" if code < 400 else "red"
    return f"[{color}]{status}[/{color}]"


def _run(tool: str, fn, *args):
    with console.status(f"ejecutando {tool}..."):
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
    summary: list[str] = []

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
    summary.append(f"{len(ports)} puerto(s) abierto(s)" if ports else "ningún puerto abierto en el escaneo rápido")

    web_ports = [p for p in ports if "http" in p["service"].lower()]
    if web_ports:
        port = web_ports[0]["port"]
        scheme = "https" if port in ("443", "8443") else "http"
        netloc = args.target if port in ("80", "443") else f"{args.target}:{port}"
        url = f"{scheme}://{netloc}"
        summary.append(f"web detectada en el puerto {port} ({url})")

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
                    gb_table.add_row(f["path"], _status_markup(f["status"]))
                console.print(gb_table)
                summary.append(f"gobuster encontró {len(findings)} ruta(s)")

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
                    ff_table.add_row(h["path"], _status_markup(h["status"]), h["size"])
                console.print(ff_table)
                summary.append(f"ffuf encontró {len(hits)} archivo(s) sensible(s)/backup(s)")

        console.print("\n[bold]nikto[/] — configuración/vulnerabilidades web")
        nikto_findings = _run("nikto", nikto.scan, url)
        if nikto_findings is not None:
            if not nikto_findings:
                console.print("  [dim]sin hallazgos[/]")
            else:
                for finding in nikto_findings:
                    console.print(f"  - {finding}", markup=False, highlight=False)
                summary.append(f"nikto reportó {len(nikto_findings)} hallazgo(s) de configuración")

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
                    summary.append(f"WordPress detectado, wpscan encontró {len(wp_findings)} hallazgo(s)")

    smb_ports = [p for p in ports if p["port"] in ("139", "445")]
    if smb_ports:
        summary.append("SMB accesible (puerto 139/445)")
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
                summary.append(f"smbclient listó {len(shares)} recurso(s) compartido(s) sin autenticación")

        console.print("\n[bold]enum4linux[/] — enumeración SMB")
        e4l_sections = _run("enum4linux", enum4linux.scan, args.target)
        if e4l_sections is not None:
            if not e4l_sections:
                console.print("  [dim]sin hallazgos[/]")
            else:
                for section, lines in e4l_sections.items():
                    console.print(f"  [italic]{section}[/]")
                    for line in lines:
                        console.print(f"    - {line}", markup=False, highlight=False)
                if "Usuarios" in e4l_sections:
                    summary.append(f"enum4linux enumeró {len(e4l_sections['Usuarios'])} usuario(s) por SMB")
                if any("allows sessions" in line for line in e4l_sections.get("Acceso", [])):
                    summary.append("SMB permite sesión anónima")

    console.print("\n[bold]Resumen[/]")
    for line in summary:
        console.print(f"  • {line}", markup=False, highlight=False)


if __name__ == "__main__":
    main()

import argparse
import concurrent.futures
import ipaddress
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from tarascan.scanners import (
    dns,
    enum4linux,
    feroxbuster,
    ffuf,
    gobuster,
    http_headers,
    hydra,
    netcat,
    netexec,
    nbtscan,
    nikto,
    nmap,
    nmap_scripts,
    nuclei,
    onesixtyone,
    searchsploit,
    smbclient,
    snmp,
    sqlmap,
    sslscan,
    subfinder,
    wafw00f,
    whatweb,
    wpscan,
)

console = Console()
error_console = Console(stderr=True, style="bold red")

# Cuántas herramientas pueden correr a la vez. Acotado a propósito: lanzar 20
# procesos contra el mismo host a la vez lo satura y puede disparar WAF/límites.
MAX_WORKERS = 8


@dataclass
class Res:
    """Resultado de una herramienta: el valor ya parseado, o el error si falló."""

    value: Any = None
    error: str = None


def _call(tool: str, fn, *args) -> Res:
    """Ejecuta una herramienta y captura su resultado o su error, sin imprimir nada."""
    try:
        return Res(value=fn(*args))
    except FileNotFoundError:
        return Res(error=f"{tool} no está instalado o no está en el PATH")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        message = f"{tool} falló (código {exc.returncode})"
        if detail:
            message += f":\n{detail[:500]}"
        return Res(error=message)
    except subprocess.TimeoutExpired:
        return Res(error=f"{tool} agotó el tiempo de espera")


def _status_markup(status: str) -> str:
    try:
        code = int(status)
    except ValueError:
        return status
    color = "green" if code < 300 else "yellow" if code < 400 else "red"
    return f"[{color}]{status}[/{color}]"


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _search_term(port: dict) -> str:
    """Construye un término razonable para searchsploit a partir del servicio/versión."""
    version = port.get("version", "")
    if version:
        # La versión suele venir como "Producto X.Y.Zpatch (detalles del SO)".
        # searchsploit acierta más con "Producto X.Y.Z": nos quedamos con las
        # palabras del producto (hasta el primer token numérico) y recortamos la
        # versión a su parte numérica (p.ej. "6.6.1p1" -> "6.6.1").
        product, numeric = [], ""
        for token in version.split():
            if re.match(r"^\d", token):
                numeric = re.match(r"^[\d.]+", token).group(0).rstrip(".")
                break
            product.append(token)
        if product and numeric:
            return f"{' '.join(product)} {numeric}"
        return " ".join(version.split()[:3])
    service = port.get("service", "")
    return service if service and service != "?" else ""


def _emit_error(res: Res) -> bool:
    """Si la herramienta falló, imprime el error y devuelve True."""
    if res.error:
        error_console.print(res.error, markup=False, highlight=False)
        return True
    return False


def _await(label: str, fut) -> Res:
    """Devuelve el resultado del future; si aún corre, muestra un spinner para
    dejar claro que el programa no está colgado, solo esperando a esa herramienta."""
    if fut.done():
        return fut.result()
    with console.status(f"[dim]ejecutando {label}...[/]", spinner="dots"):
        return fut.result()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tarascan",
        description="Recon de un objetivo encadenando herramientas ya instaladas, salida unificada por terminal.",
    )
    parser.add_argument("target", help="dominio o IP a escanear")
    parser.add_argument(
        "--sqli",
        action="store_true",
        help="lanza sqlmap contra la web detectada (intrusivo, solo objetivos autorizados)",
    )
    parser.add_argument(
        "--brute",
        metavar="SERVICIO",
        help="lanza hydra contra el objetivo para el servicio dado (ssh, ftp, http-get...); intrusivo",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="descubrimiento de contenido recursivo con feroxbuster (más lento que gobuster)",
    )
    args = parser.parse_args()
    target = args.target

    console.rule(f"[bold]tarascan[/] · recon sobre [cyan]{target}[/]")
    summary: list[str] = []

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
    is_domain = not _is_ip(target)

    # ------------------------------------------------------------------ #
    # Fase 1: lanzar lo que NO depende de nmap (DNS/OSINT, SNMP, hydra) y
    # el propio nmap. Solo esperamos a nmap para saber qué ramas abrir; el
    # resto sigue corriendo en segundo plano hasta la espera final.
    # ------------------------------------------------------------------ #
    f: dict[str, Any] = {}
    if is_domain:
        f["dns"] = executor.submit(_call, "dns", dns.scan, target)
        f["dns_axfr"] = executor.submit(_call, "dns-axfr", dns.zone_transfer, target)
        f["dns_subs"] = executor.submit(_call, "dns-brute", dns.brute_subdomains, target)
        f["subfinder"] = executor.submit(_call, "subfinder", subfinder.scan, target)
    f["onesixtyone"] = executor.submit(_call, "onesixtyone", onesixtyone.scan, target)
    f["snmp"] = executor.submit(_call, "snmp", snmp.scan, target)
    if args.brute:
        f["hydra"] = executor.submit(_call, "hydra", hydra.scan, target, args.brute)
    f["nmap"] = executor.submit(_call, "nmap", nmap.scan, target)

    with console.status("nmap: escaneando puertos (y recon inicial en paralelo)..."):
        nmap_res = f["nmap"].result()
    if nmap_res.error:
        _emit_error(nmap_res)
        executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(1)
    ports = nmap_res.value

    # ------------------------------------------------------------------ #
    # Fase 2: lanzar todo lo que depende de los puertos detectados.
    # ------------------------------------------------------------------ #
    banner_targets = [
        p for p in ports if not p.get("version") and "http" not in p["service"].lower()
    ]
    nc_futs = [(p["port"], executor.submit(_call, "nc", netcat.grab, target, p["port"])) for p in banner_targets]

    ss_futs = []
    for p in ports:
        term = _search_term(p)
        if term:
            ss_futs.append((p["port"], executor.submit(_call, "searchsploit", searchsploit.scan, term)))

    if ports:
        f["nse"] = executor.submit(_call, "nmap NSE", nmap_scripts.scan, target, [p["port"] for p in ports])

    web_ports = [p for p in ports if "http" in p["service"].lower()]
    url = None
    if web_ports:
        port = web_ports[0]["port"]
        scheme = "https" if port in ("443", "8443") else "http"
        netloc = target if port in ("80", "443") else f"{target}:{port}"
        url = f"{scheme}://{netloc}"
        f["whatweb"] = executor.submit(_call, "whatweb", whatweb.scan, url)
        f["wafw00f"] = executor.submit(_call, "wafw00f", wafw00f.scan, url)
        f["http"] = executor.submit(_call, "http-headers", http_headers.scan, url)
        f["gobuster"] = executor.submit(_call, "gobuster", gobuster.scan, url)
        if args.deep:
            f["feroxbuster"] = executor.submit(_call, "feroxbuster", feroxbuster.scan, url)
        f["ffuf"] = executor.submit(_call, "ffuf", ffuf.scan, url)
        f["nikto"] = executor.submit(_call, "nikto", nikto.scan, url)
        f["nuclei"] = executor.submit(_call, "nuclei", nuclei.scan, url)
        if args.sqli:
            f["sqli"] = executor.submit(_call, "sqlmap", sqlmap.scan, url)

    ssl_ports = [
        p for p in ports
        if p["port"] in ("443", "8443") or "https" in p["service"].lower() or "ssl" in p["service"].lower()
    ]
    ssl_futs = [(p, executor.submit(_call, "sslscan", sslscan.scan, target, p["port"])) for p in ssl_ports]

    smb_ports = [p for p in ports if p["port"] in ("139", "445")]
    if smb_ports:
        f["smbclient"] = executor.submit(_call, "smbclient", smbclient.scan, target)
        f["enum4linux"] = executor.submit(_call, "enum4linux", enum4linux.scan, target)
        f["nbtscan"] = executor.submit(_call, "nbtscan", nbtscan.scan, target)
        f["netexec"] = executor.submit(_call, "netexec", netexec.scan, target)

    # wpscan depende de que whatweb detecte WordPress; se lanza en su sección del
    # render (cuando ya tenemos el resultado de whatweb), no aquí, para no bloquear
    # la salida antes de empezar a imprimir.

    # ------------------------------------------------------------------ #
    # Render en el orden fijo de siempre, pero SIN barrera previa: cada
    # sección bloquea solo en SU herramienta (.result()). Como todas corren
    # de fondo, las que ya acabaron salen al instante y la salida va
    # apareciendo por bloques según van terminando, en orden.
    # ------------------------------------------------------------------ #
    if is_domain:
        console.print("[bold]dns[/] — registros del dominio")
        res = _await("dns", f["dns"])
        if not _emit_error(res):
            records = res.value
            if records:
                dns_table = Table(show_header=True, header_style="bold")
                dns_table.add_column("Tipo")
                dns_table.add_column("Valor")
                for rtype, values in records.items():
                    dns_table.add_row(rtype, "\n".join(values))
                console.print(dns_table)
                summary.append(f"dns resolvió {len(records)} tipo(s) de registro")
            else:
                console.print("  [dim]sin registros DNS resueltos[/]")

        console.print("\n[bold]dns[/] — transferencia de zona (AXFR)")
        res = _await("dns AXFR", f["dns_axfr"])
        if not _emit_error(res):
            axfr = res.value
            if axfr:
                for ns, names in axfr.items():
                    console.print(f"  [italic]{ns}[/] permitió AXFR — {len(names)} nombre(s)")
                    for name in names[:50]:
                        console.print(f"    - {name}", markup=False, highlight=False)
                summary.append(f"[!] AXFR permitido por {len(axfr)} NS (fuga de zona)")
            else:
                console.print("  [dim]ningún NS permitió transferencia de zona[/]")

        console.print("\n[bold]dns[/] — subdominios habituales")
        res = _await("dns subdominios", f["dns_subs"])
        if not _emit_error(res):
            subs = res.value
            if subs:
                sub_table = Table(show_header=True, header_style="bold")
                sub_table.add_column("Subdominio")
                sub_table.add_column("IP")
                for s in subs:
                    sub_table.add_row(s["host"], s["ip"])
                console.print(sub_table)
                summary.append(f"dns encontró {len(subs)} subdominio(s)")
            else:
                console.print("  [dim]sin subdominios de la lista corta[/]")

        console.print("\n[bold]subfinder[/] — subdominios (OSINT pasivo)")
        res = _await("subfinder", f["subfinder"])
        if not _emit_error(res):
            passive = res.value
            if passive:
                for name in passive[:60]:
                    console.print(f"  - {name}", markup=False, highlight=False)
                if len(passive) > 60:
                    console.print(f"  [dim]... y {len(passive) - 60} más[/]")
                summary.append(f"subfinder encontró {len(passive)} subdominio(s) por OSINT")
            else:
                console.print("  [dim]sin subdominios por fuentes pasivas[/]")

    console.print("\n[bold]nmap[/] — puertos abiertos")
    if not ports:
        console.print("  [dim]sin puertos abiertos en el escaneo rápido (-F)[/]")
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Puerto")
        table.add_column("Proto")
        table.add_column("Servicio")
        table.add_column("Versión")
        for p in ports:
            table.add_row(p["port"], p["proto"], p["service"], p.get("version", "") or "[dim]?[/]")
        console.print(table)
    summary.append(f"{len(ports)} puerto(s) abierto(s)" if ports else "ningún puerto abierto en el escaneo rápido")

    if nc_futs:
        console.print("\n[bold]nc[/] — banners de puertos sin versión")
        rows = []
        for port, fut in nc_futs:
            res = _await(f"nc {port}", fut)
            if not res.error and res.value:
                rows.append((port, res.value))
        if rows:
            nc_table = Table(show_header=True, header_style="bold")
            nc_table.add_column("Puerto")
            nc_table.add_column("Banner")
            for port, banner in rows:
                nc_table.add_row(port, banner)
            console.print(nc_table)
        else:
            console.print("  [dim]ningún puerto devolvió banner[/]")

    exploit_rows = []
    for port, fut in ss_futs:
        res = _await(f"searchsploit {port}", fut)
        if not res.error and res.value:
            for r in res.value:
                exploit_rows.append((port, r))
    if exploit_rows:
        console.print("\n[bold]searchsploit[/] — exploits conocidos (exploit-db)")
        ss_table = Table(show_header=True, header_style="bold")
        ss_table.add_column("Puerto")
        ss_table.add_column("EDB-ID")
        ss_table.add_column("Tipo")
        ss_table.add_column("Título")
        for port, r in exploit_rows:
            ss_table.add_row(port, r["edb"], r["type"], r["title"])
        console.print(ss_table)
        summary.append(f"searchsploit encontró {len(exploit_rows)} exploit(s) potencial(es)")

    if ports:
        console.print("\n[bold]nmap NSE[/] — scripts default + vuln (safe)")
        res = _await("nmap NSE", f["nse"])
        if not _emit_error(res):
            nse = res.value
            if nse:
                for where, lines in nse.items():
                    console.print(f"  [italic]{where}[/]")
                    for line in lines[:40]:
                        console.print(f"    - {line}", markup=False, highlight=False)
                    if len(lines) > 40:
                        console.print(f"    [dim]... y {len(lines) - 40} línea(s) más[/]")
                summary.append(f"nmap NSE devolvió salida en {len(nse)} ubicación(es)")
            else:
                console.print("  [dim]sin salida relevante de los scripts[/]")

    if web_ports:
        summary.append(f"web detectada en el puerto {web_ports[0]['port']} ({url})")

        console.print("\n[bold]whatweb[/] — tecnologías detectadas")
        res = _await("whatweb", f["whatweb"])
        info = res.value if not res.error else None
        if not _emit_error(res):
            if not info or not info["plugins"]:
                console.print("  [dim]sin resultados[/]")
            else:
                ww_table = Table(show_header=True, header_style="bold")
                ww_table.add_column("Plugin")
                ww_table.add_column("Detalle")
                for name, value in info["plugins"].items():
                    ww_table.add_row(name, value)
                console.print(ww_table)
            # wpscan solo si whatweb vio WordPress; se lanza ahora para que corra
            # mientras se imprimen gobuster/nikto/nuclei y esté listo en su sección.
            if info and "WordPress" in info["plugins"]:
                f["wpscan"] = executor.submit(_call, "wpscan", wpscan.scan, url)

        console.print("\n[bold]wafw00f[/] — detección de WAF")
        res = _await("wafw00f", f["wafw00f"])
        if not _emit_error(res):
            waf = res.value
            if waf["detected"]:
                detail = waf["firewall"] + (f" ({waf['manufacturer']})" if waf.get("manufacturer") else "")
                console.print(f"  [yellow]WAF detectado:[/] {escape(detail)}", highlight=False)
                console.print("  [dim]ojo: con WAF, muchos 403 de gobuster/ffuf pueden ser falsos positivos[/]")
                summary.append(f"WAF detectado: {waf['firewall']}")
            else:
                console.print("  [dim]sin WAF detectado[/]")

        console.print("\n[bold]http[/] — cabeceras de seguridad y métodos")
        res = _await("http-headers", f["http"])
        if not _emit_error(res):
            hdr = res.value
            if hdr["leaks"]:
                for name, value in hdr["leaks"].items():
                    console.print(f"  {name}: {value}", markup=False, highlight=False)
            if hdr["missing"]:
                console.print(f"  cabeceras de seguridad ausentes: {len(hdr['missing'])}")
                for desc in hdr["missing"]:
                    console.print(f"    - {desc}", markup=False, highlight=False)
                summary.append(f"faltan {len(hdr['missing'])} cabecera(s) de seguridad")
            else:
                console.print("  [dim]todas las cabeceras de seguridad revisadas están presentes[/]")
            if hdr["methods"]:
                console.print(f"  métodos permitidos: {', '.join(hdr['methods'])}")
            if hdr["dangerous_methods"]:
                console.print(f"  [red]métodos peligrosos habilitados:[/] {', '.join(hdr['dangerous_methods'])}")
                summary.append(f"[!] métodos HTTP peligrosos: {', '.join(hdr['dangerous_methods'])}")

        console.print("\n[bold]gobuster[/] — rutas encontradas")
        res = _await("gobuster", f["gobuster"])
        if not _emit_error(res):
            findings = res.value
            if not findings:
                console.print("  [dim]sin rutas encontradas con la wordlist por defecto[/]")
            else:
                gb_table = Table(show_header=True, header_style="bold")
                gb_table.add_column("Ruta")
                gb_table.add_column("Status")
                for item in findings:
                    gb_table.add_row(item["path"], _status_markup(item["status"]))
                console.print(gb_table)
                summary.append(f"gobuster encontró {len(findings)} ruta(s)")

        if args.deep:
            console.print("\n[bold]feroxbuster[/] — descubrimiento recursivo")
            res = _await("feroxbuster", f["feroxbuster"])
            if not _emit_error(res):
                fx = res.value
                if not fx:
                    console.print("  [dim]sin rutas adicionales[/]")
                else:
                    fx_table = Table(show_header=True, header_style="bold")
                    fx_table.add_column("Ruta")
                    fx_table.add_column("Status")
                    for item in fx:
                        fx_table.add_row(item["path"], _status_markup(item["status"]))
                    console.print(fx_table)
                    summary.append(f"feroxbuster encontró {len(fx)} ruta(s) (recursivo)")

        console.print("\n[bold]ffuf[/] — archivos sensibles/backups")
        res = _await("ffuf", f["ffuf"])
        if not _emit_error(res):
            hits = res.value
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
        res = _await("nikto", f["nikto"])
        if not _emit_error(res):
            nikto_findings = res.value
            if not nikto_findings:
                console.print("  [dim]sin hallazgos[/]")
            else:
                for finding in nikto_findings:
                    console.print(f"  - {finding}", markup=False, highlight=False)
                summary.append(f"nikto reportó {len(nikto_findings)} hallazgo(s) de configuración")

        console.print("\n[bold]nuclei[/] — vulnerabilidades por plantillas")
        res = _await("nuclei", f["nuclei"])
        if not _emit_error(res):
            nuclei_findings = res.value
            if not nuclei_findings:
                console.print("  [dim]sin hallazgos (low+)[/]")
            else:
                nu_table = Table(show_header=True, header_style="bold")
                nu_table.add_column("Severidad")
                nu_table.add_column("Plantilla")
                nu_table.add_column("Nombre")
                sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan"}
                for item in nuclei_findings[:60]:
                    color = sev_color.get(item["severity"], "white")
                    nu_table.add_row(f"[{color}]{item['severity']}[/]", item["template"], item["name"])
                console.print(nu_table)
                if len(nuclei_findings) > 60:
                    console.print(f"  [dim]... y {len(nuclei_findings) - 60} hallazgo(s) más[/]")
                graves = sum(1 for item in nuclei_findings if item["severity"] in ("critical", "high"))
                summary.append(f"nuclei: {len(nuclei_findings)} hallazgo(s)" + (f", {graves} grave(s)" if graves else ""))

        if "wpscan" in f:
            console.print("\n[bold]wpscan[/] — WordPress detectado")
            res = _await("wpscan", f["wpscan"])
            if not _emit_error(res):
                wp_findings = res.value
                if not wp_findings:
                    console.print("  [dim]sin hallazgos[/]")
                else:
                    wp_table = Table(show_header=True, header_style="bold")
                    wp_table.add_column("Tipo")
                    wp_table.add_column("Detalle")
                    for item in wp_findings:
                        wp_table.add_row(item["tipo"], item["detalle"])
                    console.print(wp_table)
                    summary.append(f"WordPress detectado, wpscan encontró {len(wp_findings)} hallazgo(s)")

        if args.sqli:
            console.print("\n[bold]sqlmap[/] — prueba de inyección SQL [red](intrusivo)[/]")
            res = _await("sqlmap", f["sqli"])
            if not _emit_error(res):
                sqli_findings = res.value
                if not sqli_findings:
                    console.print("  [dim]sin inyección SQL detectada[/]")
                else:
                    for line in sqli_findings:
                        console.print(f"  - {line}", markup=False, highlight=False)
                    summary.append(f"sqlmap reportó {len(sqli_findings)} indicio(s) de SQLi")

    for p, fut in ssl_futs:
        console.print(f"\n[bold]sslscan[/] — TLS en el puerto {p['port']}")
        res = _await(f"sslscan {p['port']}", fut)
        if _emit_error(res):
            continue
        tls = res.value
        if tls["protocols"]:
            console.print(f"  protocolos habilitados: {', '.join(tls['protocols'])}")
        if tls["insecure_protocols"]:
            console.print(f"  [red]protocolos inseguros:[/] {', '.join(tls['insecure_protocols'])}")
            summary.append(f"[!] TLS inseguro en {p['port']}: {', '.join(tls['insecure_protocols'])}")
        if tls["weak_ciphers"]:
            console.print(f"  [red]cifrados débiles:[/] {len(tls['weak_ciphers'])}")
            for c in tls["weak_ciphers"]:
                console.print(f"    - {c}", markup=False, highlight=False)
        for key, value in tls["cert"].items():
            console.print(f"  cert {key}: {value}", markup=False, highlight=False)
        if tls["cert"].get("estado") == "CADUCADO":
            summary.append(f"[!] certificado TLS caducado en el puerto {p['port']}")
        if not tls["protocols"] and not tls["cert"]:
            console.print("  [dim]sin handshake TLS (¿requiere SNI/hostname?)[/]")

    if smb_ports:
        summary.append("SMB accesible (puerto 139/445)")
        console.print("\n[bold]smbclient[/] — recursos compartidos")
        res = _await("smbclient", f["smbclient"])
        if not _emit_error(res):
            shares = res.value
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
        res = _await("enum4linux", f["enum4linux"])
        if not _emit_error(res):
            e4l_sections = res.value
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

        console.print("\n[bold]nbtscan[/] — nombres NetBIOS")
        res = _await("nbtscan", f["nbtscan"])
        if not _emit_error(res):
            nb = res.value
            if not nb:
                console.print("  [dim]sin respuesta NetBIOS[/]")
            else:
                nb_table = Table(show_header=True, header_style="bold")
                nb_table.add_column("IP")
                nb_table.add_column("Nombre")
                nb_table.add_column("MAC")
                for h in nb:
                    nb_table.add_row(h["ip"], h["name"], h["mac"])
                console.print(nb_table)

        console.print("\n[bold]netexec[/] — enumeración SMB (sesión nula)")
        res = _await("netexec", f["netexec"])
        if not _emit_error(res):
            nxc = res.value
            if nxc["host"]:
                console.print("  [italic]Host[/]")
                for line in nxc["host"]:
                    console.print(f"    - {line}", markup=False, highlight=False)
            if nxc["shares"]:
                console.print("  [italic]Recursos[/]")
                for line in nxc["shares"]:
                    console.print(f"    - {line}", markup=False, highlight=False)
                summary.append(f"netexec listó {len(nxc['shares'])} recurso(s) por sesión nula")
            if not nxc["host"] and not nxc["shares"]:
                console.print("  [dim]sin datos por sesión nula[/]")

    console.print("\n[bold]onesixtyone[/] — comunidades SNMP")
    res = _await("onesixtyone", f["onesixtyone"])
    if not _emit_error(res):
        communities = res.value
        if communities:
            for c in communities:
                console.print(f"  [yellow]comunidad válida:[/] {escape(c['community'])}", highlight=False)
                if c["info"]:
                    console.print(f"    {c['info']}", markup=False, highlight=False)
            summary.append(f"[!] SNMP con comunidad(es) válida(s): {', '.join(c['community'] for c in communities)}")
        else:
            console.print("  [dim]sin comunidades SNMP válidas[/]")

    console.print("\n[bold]snmp[/] — enumeración con comunidad 'public'")
    res = _await("snmp", f["snmp"])
    if not _emit_error(res):
        snmp_findings = res.value
        if not snmp_findings:
            console.print("  [dim]sin respuesta SNMP con 'public'[/]")
        else:
            for line in snmp_findings[:40]:
                console.print(f"  - {line}", markup=False, highlight=False)
            if len(snmp_findings) > 40:
                console.print(f"  [dim]... y {len(snmp_findings) - 40} línea(s) más[/]")
            summary.append(f"[!] SNMP responde con 'public' ({len(snmp_findings)} valor(es))")

    if args.brute:
        console.print(f"\n[bold]hydra[/] — fuerza bruta de {args.brute} [red](intrusivo)[/]")
        res = _await("hydra", f["hydra"])
        if not _emit_error(res):
            creds = res.value
            if not creds:
                console.print("  [dim]sin credenciales válidas con las wordlists por defecto[/]")
            else:
                hy_table = Table(show_header=True, header_style="bold")
                hy_table.add_column("Usuario")
                hy_table.add_column("Contraseña")
                for c in creds:
                    hy_table.add_row(c["login"], c["password"])
                console.print(hy_table)
                summary.append(f"hydra encontró {len(creds)} credencial(es) válida(s)")

    executor.shutdown(wait=True)

    console.print("\n[bold]Resumen[/]")
    for line in summary:
        console.print(f"  • {line}", markup=False, highlight=False)


if __name__ == "__main__":
    main()

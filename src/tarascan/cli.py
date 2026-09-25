import argparse
import concurrent.futures
import ipaddress
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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
    vhost,
    wafw00f,
    whatweb,
    wpscan,
)

console = Console()

# Paleta (sin azul): naranja para acentos/títulos, morado secundario, gris para
# las explicaciones y bordes.
ORANGE = "#ff9e64"
PURPLE = "#9d7cd8"
GREY = "#787c99"

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
    except Exception as exc:  # noqa: BLE001 - un fallo de una herramienta no debe tumbar el resto
        return Res(error=f"{tool} error: {exc}")


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


def _await(label: str, fut) -> Res:
    """Devuelve el resultado del future; si aún corre, muestra un spinner con la
    herramienta que se está lanzando (el resto corre en paralelo de fondo)."""
    if fut.done():
        return fut.result()
    with console.status(f"[{ORANGE}]lanzando {label}[/][{GREY}]… (otras herramientas en paralelo)[/]", spinner="dots"):
        return fut.result()


def _dim(text: str) -> Text:
    """Línea de explicación (qué mira la herramienta / cómo leer el resultado)."""
    return Text(text, style=f"italic {GREY}")


def _note(text: str) -> str:
    """Línea de interpretación de un hallazgo (en naranja, con flecha)."""
    return f"[{ORANGE}]→ {text}[/]"


def _panel(title: str, desc: str, body: list, border: str = GREY) -> None:
    """Imprime una sección dentro de una caja: título, explicación y contenido."""
    parts: list = []
    if desc:
        parts.append(_dim(desc))
    parts.extend(body)
    if not parts:
        parts.append(Text("sin resultados", style=GREY))
    console.print(
        Panel(
            Group(*parts),
            title=f"[bold {ORANGE}]{title}[/]",
            title_align="left",
            border_style=border,
            padding=(0, 1),
        )
    )


def _err_body(res: Res) -> list:
    """Cuerpo de panel para una herramienta que falló. Traduce los fallos típicos
    (no son bugs: son cómo responde el objetivo) a una explicación clara."""
    err = res.error or ""
    low = err.lower()
    friendly = None
    if "unrecognized name" in low or "tlsv1_unrecognized" in low or "sni" in low:
        friendly = ("el servidor exige SNI (nombre de dominio) para el TLS, típico de un reverse-proxy. "
                    "Escanéalo por su dominio real, no por la IP.")
    elif "non existing urls" in low or "wildcard" in low or "matches the provided options" in low:
        friendly = ("el servidor responde igual a cualquier ruta (comodín): no se pueden distinguir "
                    "rutas reales de las inventadas, así que se aborta para no dar falsos positivos.")
    elif "unable to connect" in low or "connection refused" in low or "failed to connect" in low:
        friendly = "no se pudo conectar al servicio (¿requiere dominio/SNI, o está filtrado?)."

    if friendly:
        return [Text(f"→ {friendly}", style=ORANGE), Text(err, style=GREY)]
    return [Text(err, style="bold red")]


def _table(*columns: str) -> Table:
    t = Table(show_header=True, header_style=f"bold {ORANGE}")
    for c in columns:
        t.add_column(c)
    return t


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tarascan",
        description="Recon de un objetivo encadenando herramientas ya instaladas, salida unificada por terminal.",
    )
    parser.add_argument("target", help="dominio o IP a escanear")
    parser.add_argument(
        "--full",
        action="store_true",
        help="nmap escanea los 65535 puertos (-p-) en vez del top-100 (más lento)",
    )
    parser.add_argument(
        "--only",
        metavar="LISTA",
        help="ejecuta SOLO estas herramientas (coma: p.ej. nmap,nuclei,smbclient)",
    )
    parser.add_argument(
        "--skip",
        metavar="LISTA",
        help="omite estas herramientas (coma: p.ej. nuclei,nikto)",
    )
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

    # Selección de herramientas. nmap es la base y siempre corre.
    only = {x.strip() for x in args.only.split(",")} if args.only else None
    skip = {x.strip() for x in args.skip.split(",")} if args.skip else set()

    def on(name: str) -> bool:
        if name == "nmap":
            return True
        return (only is None or name in only) and name not in skip

    console.print()
    console.rule(f"[bold {ORANGE}]tarascan[/] · recon sobre [{PURPLE}]{escape(target)}[/]", style=GREY)
    console.print()
    summary: list[str] = []

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
    is_domain = not _is_ip(target)

    # ------------------------------------------------------------------ #
    # Fase 1: lo que NO depende de nmap. Solo esperamos a nmap para ramificar.
    # ------------------------------------------------------------------ #
    f: dict[str, Any] = {}
    if is_domain:
        if on("dns"):
            f["dns"] = executor.submit(_call, "dns", dns.scan, target)
            f["dns_axfr"] = executor.submit(_call, "dns-axfr", dns.zone_transfer, target)
            f["dns_subs"] = executor.submit(_call, "dns-brute", dns.brute_subdomains, target)
        if on("subfinder"):
            f["subfinder"] = executor.submit(_call, "subfinder", subfinder.scan, target)
    if on("onesixtyone"):
        f["onesixtyone"] = executor.submit(_call, "onesixtyone", onesixtyone.scan, target)
    if on("snmp"):
        f["snmp"] = executor.submit(_call, "snmp", snmp.scan, target)
    if args.brute and on("hydra"):
        f["hydra"] = executor.submit(_call, "hydra", hydra.scan, target, args.brute)
    f["nmap"] = executor.submit(_call, "nmap", nmap.scan, target, args.full)

    scope = "65535 puertos" if args.full else "top-100"
    with console.status(f"[{ORANGE}]lanzando nmap[/][{GREY}]… ({scope}; recon inicial en paralelo)[/]", spinner="dots"):
        nmap_res = f["nmap"].result()
    if nmap_res.error:
        _panel("nmap · puertos abiertos", "servicios y versiones expuestos en el objetivo", _err_body(nmap_res), border="red")
        executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(1)
    ports = nmap_res.value

    # ------------------------------------------------------------------ #
    # Fase 2: lo que depende de los puertos detectados.
    # ------------------------------------------------------------------ #
    banner_targets = [
        p for p in ports if not p.get("version") and "http" not in p["service"].lower()
    ]
    nc_futs = (
        [(p["port"], executor.submit(_call, "nc", netcat.grab, target, p["port"])) for p in banner_targets]
        if on("nc") else []
    )

    ss_futs = []
    if on("searchsploit"):
        for p in ports:
            term = _search_term(p)
            if term:
                ss_futs.append((p["port"], executor.submit(_call, "searchsploit", searchsploit.scan, term)))

    if ports and on("nse"):
        f["nse"] = executor.submit(_call, "nmap NSE", nmap_scripts.scan, target, [p["port"] for p in ports])

    # Todos los puertos web (no solo el primero): cada uno se analiza por separado.
    web_ports = [p for p in ports if "http" in p["service"].lower()]
    web_targets = []
    for p in web_ports:
        prt = p["port"]
        scheme = "https" if prt in ("443", "8443") else "http"
        netloc = target if prt in ("80", "443") else f"{target}:{prt}"
        web_targets.append((prt, scheme, f"{scheme}://{netloc}"))

    webf: dict[str, dict] = {}
    for prt, scheme, url in web_targets:
        d: dict[str, Any] = {}
        if on("whatweb"):
            d["whatweb"] = executor.submit(_call, "whatweb", whatweb.scan, url)
        if on("wafw00f"):
            d["wafw00f"] = executor.submit(_call, "wafw00f", wafw00f.scan, url)
        if on("http"):
            d["http"] = executor.submit(_call, "http-headers", http_headers.scan, url)
        if on("vhost") and scheme == "http":
            d["vhost"] = executor.submit(_call, "vhost", vhost.scan, url, target if is_domain else None)
        if on("gobuster"):
            d["gobuster"] = executor.submit(_call, "gobuster", gobuster.scan, url)
        if args.deep and on("feroxbuster"):
            d["feroxbuster"] = executor.submit(_call, "feroxbuster", feroxbuster.scan, url)
        if on("ffuf"):
            d["ffuf"] = executor.submit(_call, "ffuf", ffuf.scan, url)
        if on("nikto"):
            d["nikto"] = executor.submit(_call, "nikto", nikto.scan, url)
        if on("nuclei"):
            d["nuclei"] = executor.submit(_call, "nuclei", nuclei.scan, url)
        if args.sqli and on("sqlmap"):
            d["sqli"] = executor.submit(_call, "sqlmap", sqlmap.scan, url)
        webf[prt] = d

    ssl_ports = [
        p for p in ports
        if p["port"] in ("443", "8443") or "https" in p["service"].lower() or "ssl" in p["service"].lower()
    ]
    ssl_futs = (
        [(p, executor.submit(_call, "sslscan", sslscan.scan, target, p["port"])) for p in ssl_ports]
        if on("sslscan") else []
    )

    smb_ports = [p for p in ports if p["port"] in ("139", "445")]
    if smb_ports:
        if on("smbclient"):
            f["smbclient"] = executor.submit(_call, "smbclient", smbclient.scan, target)
        if on("enum4linux"):
            f["enum4linux"] = executor.submit(_call, "enum4linux", enum4linux.scan, target)
        if on("nbtscan"):
            f["nbtscan"] = executor.submit(_call, "nbtscan", nbtscan.scan, target)
        if on("netexec"):
            f["netexec"] = executor.submit(_call, "netexec", netexec.scan, target)

    # ------------------------------------------------------------------ #
    # Render: cada sección en su caja, en orden fijo, sin barrera previa.
    # ------------------------------------------------------------------ #
    if "dns" in f:
        res = _await("dns", f["dns"])
        if res.error:
            body = _err_body(res)
        else:
            records = res.value
            if records:
                t = _table("Tipo", "Valor")
                for rtype, values in records.items():
                    t.add_row(rtype, "\n".join(values))
                body = [t]
                summary.append(f"dns resolvió {len(records)} tipo(s) de registro")
            else:
                body = [Text("sin registros DNS resueltos", style=GREY)]
        _panel("dns · registros del dominio", "qué direcciones, correo y servidores publica el dominio", body)

        res = _await("dns AXFR", f["dns_axfr"])
        if res.error:
            body = _err_body(res)
        else:
            axfr = res.value
            if axfr:
                body = []
                for ns, names in axfr.items():
                    body.append(Text(f"{ns} permitió AXFR — {len(names)} nombre(s)", style=PURPLE))
                    body.extend(Text(f"  {name}") for name in names[:50])
                body.append(_note("fuga de toda la zona DNS: un fallo grave de configuración"))
                summary.append(f"[!] AXFR permitido por {len(axfr)} NS (fuga de zona)")
            else:
                body = [Text("ningún NS permitió transferencia de zona (bien)", style=GREY)]
        _panel("dns · transferencia de zona (AXFR)", "si un servidor DNS deja copiar toda la zona sin permiso", body)

        res = _await("dns subdominios", f["dns_subs"])
        if res.error:
            body = _err_body(res)
        else:
            subs = res.value
            if subs:
                t = _table("Subdominio", "IP")
                for s in subs:
                    t.add_row(s["host"], s["ip"])
                body = [t]
                summary.append(f"dns encontró {len(subs)} subdominio(s)")
            else:
                body = [Text("sin subdominios de la lista corta", style=GREY)]
        _panel("dns · subdominios habituales", "prueba nombres comunes (www, mail, dev...) a fuerza bruta", body)

    if "subfinder" in f:
        res = _await("subfinder", f["subfinder"])
        if res.error:
            body = _err_body(res)
        else:
            passive = res.value
            if passive:
                body = [Text(name) for name in passive[:60]]
                if len(passive) > 60:
                    body.append(Text(f"... y {len(passive) - 60} más", style=GREY))
                summary.append(f"subfinder encontró {len(passive)} subdominio(s) por OSINT")
            else:
                body = [Text("sin subdominios por fuentes pasivas", style=GREY)]
        _panel("subfinder · subdominios (OSINT)", "subdominios recopilados de fuentes públicas, sin tocar el objetivo", body)

    # --- nmap ---
    if not ports:
        body = [Text("sin puertos abiertos en el escaneo", style=GREY)]
    else:
        t = _table("Puerto", "Proto", "Servicio", "Versión")
        for p in ports:
            t.add_row(p["port"], p["proto"], p["service"], p.get("version", "") or "?")
        body = [t]
    _panel("nmap · puertos abiertos", "qué servicios y versiones expone el objetivo", body)
    summary.append(f"{len(ports)} puerto(s) abierto(s)" if ports else "ningún puerto abierto en el escaneo")

    # --- nc (banners) ---
    if nc_futs:
        rows = []
        for port, fut in nc_futs:
            res = _await(f"nc {port}", fut)
            if not res.error and res.value:
                rows.append((port, res.value))
        if rows:
            t = _table("Puerto", "Banner")
            for port, banner in rows:
                t.add_row(port, banner)
            body = [t]
        else:
            body = [Text("ningún puerto devolvió banner", style=GREY)]
        _panel("nc · banners", "intenta identificar puertos que nmap no supo versionar", body)

    # --- searchsploit ---
    exploit_rows = []
    for port, fut in ss_futs:
        res = _await(f"searchsploit {port}", fut)
        if not res.error and res.value:
            for r in res.value:
                exploit_rows.append((port, r))
    if exploit_rows:
        t = _table("Puerto", "EDB-ID", "Tipo", "Título")
        for port, r in exploit_rows:
            t.add_row(port, r["edb"], r["type"], r["title"])
        body = [t, _note("son exploits públicos para esas versiones; confirma que la versión sea explotable antes de fiarte")]
        _panel("searchsploit · exploits conocidos", "busca en exploit-db exploits para las versiones detectadas", body)
        summary.append(f"searchsploit encontró {len(exploit_rows)} exploit(s) potencial(es)")

    # --- nmap NSE ---
    if "nse" in f:
        res = _await("nmap NSE", f["nse"])
        if res.error:
            body = _err_body(res)
        else:
            nse = res.value
            if nse:
                body = []
                for where, lines in nse.items():
                    body.append(Text(where, style=PURPLE))
                    body.extend(Text(f"  {line}") for line in lines[:40])
                    if len(lines) > 40:
                        body.append(Text(f"  ... y {len(lines) - 40} línea(s) más", style=GREY))
                summary.append(f"nmap NSE devolvió salida en {len(nse)} ubicación(es)")
            else:
                body = [Text("sin salida relevante de los scripts", style=GREY)]
        _panel("nmap NSE · scripts", "comprobaciones de scripts de nmap (default + vuln seguros)", body)

    # --- rama web: una tanda de paneles por CADA puerto web ---
    for prt, scheme, url in web_targets:
        d = webf.get(prt, {})
        summary.append(f"web detectada en el puerto {prt} ({url})")

        info = None
        if "whatweb" in d:
            res = _await(f"whatweb {url}", d["whatweb"])
            info = res.value if not res.error else None
            if res.error:
                body = _err_body(res)
            elif not info or not info["plugins"]:
                body = [Text("sin resultados", style=GREY)]
            else:
                t = _table("Plugin", "Detalle")
                for name, value in info["plugins"].items():
                    t.add_row(name, value)
                body = [t]
            _panel(f"whatweb · tecnologías ({url})", "qué software y frameworks usa el servidor web", body)
            if info and "WordPress" in info["plugins"] and on("wpscan"):
                d["wpscan"] = executor.submit(_call, "wpscan", wpscan.scan, url)

        if "vhost" in d:
            res = _await(f"vhost {url}", d["vhost"])
            if res.error:
                body = _err_body(res)
            else:
                vhosts = res.value
                if not vhosts:
                    body = [Text("sin vhosts distintos del sitio por defecto", style=GREY)]
                else:
                    t = _table("Host", "Status", "Tamaño")
                    for v in vhosts:
                        t.add_row(v["host"], _status_markup(v["status"]), v["size"])
                    body = [t, _note("hay sitios servidos por nombre distintos al de por defecto: escanéalos con su Host real")]
                    summary.append(f"vhost encontró {len(vhosts)} sitio(s) por nombre en :{prt}")
            _panel(f"vhost · sitios por nombre ({url})", "prueba cabeceras Host para descubrir webs detrás del mismo puerto/proxy", body)

        if "wafw00f" in d:
            res = _await(f"wafw00f {url}", d["wafw00f"])
            if res.error:
                body = _err_body(res)
            else:
                waf = res.value
                if waf["detected"]:
                    detail = waf["firewall"] + (f" ({waf['manufacturer']})" if waf.get("manufacturer") else "")
                    body = [Text(f"WAF detectado: {detail}", style="bold yellow"),
                            _note("con WAF, muchos 403 de gobuster/ffuf pueden ser falsos positivos")]
                    summary.append(f"WAF detectado en :{prt}: {waf['firewall']}")
                else:
                    body = [Text("sin WAF detectado", style=GREY)]
            _panel(f"wafw00f · cortafuegos web ({url})", "si hay un WAF filtrando las peticiones", body)

        if "http" in d:
            res = _await(f"http-headers {url}", d["http"])
            if res.error:
                body = _err_body(res)
            else:
                hdr = res.value
                body = []
                for name, value in hdr["leaks"].items():
                    body.append(Text(f"{name}: {value}", style=GREY))
                if hdr["missing"]:
                    body.append(Text(f"cabeceras de seguridad ausentes: {len(hdr['missing'])}", style="yellow"))
                    body.extend(Text(f"  {desc}") for desc in hdr["missing"])
                    body.append(_note("el navegador queda con menos defensas (clickjacking, XSS, sniffing de tipo)"))
                    summary.append(f"faltan {len(hdr['missing'])} cabecera(s) de seguridad en :{prt}")
                else:
                    body.append(Text("todas las cabeceras de seguridad revisadas están presentes", style="green"))
                if hdr["methods"]:
                    body.append(Text(f"métodos permitidos: {', '.join(hdr['methods'])}"))
                if hdr["dangerous_methods"]:
                    body.append(Text(f"métodos peligrosos habilitados: {', '.join(hdr['dangerous_methods'])}", style="bold red"))
                    summary.append(f"[!] métodos HTTP peligrosos en :{prt}: {', '.join(hdr['dangerous_methods'])}")
            _panel(f"http · cabeceras y métodos ({url})", "qué protecciones de navegador faltan y qué métodos HTTP acepta", body)

        if "gobuster" in d:
            res = _await(f"gobuster {url}", d["gobuster"])
            if res.error:
                body = _err_body(res)
            else:
                findings = res.value
                if not findings:
                    body = [Text("sin rutas encontradas con la wordlist por defecto", style=GREY)]
                else:
                    t = _table("Ruta", "Status")
                    for item in findings:
                        t.add_row(item["path"], _status_markup(item["status"]))
                    body = [t]
                    summary.append(f"gobuster encontró {len(findings)} ruta(s) en :{prt}")
            _panel(f"gobuster · rutas web ({url})", "descubre directorios y ficheros por fuerza bruta con una wordlist", body)

        if "feroxbuster" in d:
            res = _await(f"feroxbuster {url}", d["feroxbuster"])
            if res.error:
                body = _err_body(res)
            else:
                fx = res.value
                if not fx:
                    body = [Text("sin rutas adicionales", style=GREY)]
                else:
                    t = _table("Ruta", "Status")
                    for item in fx:
                        t.add_row(item["path"], _status_markup(item["status"]))
                    body = [t]
                    summary.append(f"feroxbuster encontró {len(fx)} ruta(s) (recursivo) en :{prt}")
            _panel(f"feroxbuster · descubrimiento recursivo ({url})", "como gobuster pero entrando en los subdirectorios que encuentra", body)

        if "ffuf" in d:
            res = _await(f"ffuf {url}", d["ffuf"])
            if res.error:
                body = _err_body(res)
            else:
                hits = res.value
                if not hits:
                    body = [Text("sin hallazgos entre los nombres habituales probados", style=GREY)]
                else:
                    t = _table("Ruta", "Status", "Tamaño")
                    for h in hits:
                        t.add_row(h["path"], _status_markup(h["status"]), h["size"])
                    body = [t, _note("verifica a mano: con WAF, un 403/200 no confirma que el fichero exista")]
                    summary.append(f"ffuf encontró {len(hits)} archivo(s) sensible(s)/backup(s) en :{prt}")
            _panel(f"ffuf · ficheros sensibles ({url})", "prueba nombres de ficheros de config/backup habituales (.env, .git, backups...)", body)

        if "nikto" in d:
            res = _await(f"nikto {url}", d["nikto"])
            if res.error:
                body = _err_body(res)
            else:
                nikto_findings = res.value
                if not nikto_findings:
                    body = [Text("sin hallazgos", style=GREY)]
                else:
                    body = [Text(f"  {finding}") for finding in nikto_findings]
                    summary.append(f"nikto reportó {len(nikto_findings)} hallazgo(s) en :{prt}")
            _panel(f"nikto · configuración web ({url})", "problemas de configuración y vulnerabilidades web conocidas", body)

        if "nuclei" in d:
            res = _await(f"nuclei {url}", d["nuclei"])
            if res.error:
                body = _err_body(res)
            else:
                nuclei_findings = res.value
                if not nuclei_findings:
                    body = [Text("sin hallazgos (low+)", style=GREY)]
                else:
                    t = _table("Severidad", "Plantilla", "Nombre")
                    sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": PURPLE}
                    for item in nuclei_findings[:60]:
                        color = sev_color.get(item["severity"], "white")
                        t.add_row(f"[{color}]{item['severity']}[/]", item["template"], item["name"])
                    body = [t]
                    if len(nuclei_findings) > 60:
                        body.append(Text(f"... y {len(nuclei_findings) - 60} hallazgo(s) más", style=GREY))
                    graves = sum(1 for item in nuclei_findings if item["severity"] in ("critical", "high"))
                    if graves:
                        body.append(_note(f"{graves} hallazgo(s) grave(s) (high/critical): revísalos primero"))
                    summary.append(f"nuclei en :{prt}: {len(nuclei_findings)} hallazgo(s)" + (f", {graves} grave(s)" if graves else ""))
            _panel(f"nuclei · vulnerabilidades ({url})", "detección por plantillas de vulnerabilidades y exposiciones conocidas", body)

        if "wpscan" in d:
            res = _await(f"wpscan {url}", d["wpscan"])
            if res.error:
                body = _err_body(res)
            else:
                wp_findings = res.value
                if not wp_findings:
                    body = [Text("sin hallazgos", style=GREY)]
                else:
                    t = _table("Tipo", "Detalle")
                    for item in wp_findings:
                        t.add_row(item["tipo"], item["detalle"])
                    body = [t]
                    summary.append(f"WordPress en :{prt}, wpscan encontró {len(wp_findings)} hallazgo(s)")
            _panel(f"wpscan · WordPress ({url})", "enumeración específica de WordPress (versión, plugins, exposiciones)", body)

        if "sqli" in d:
            res = _await(f"sqlmap {url}", d["sqli"])
            if res.error:
                body = _err_body(res)
            else:
                sqli_findings = res.value
                if not sqli_findings:
                    body = [Text("sin inyección SQL detectada", style=GREY)]
                else:
                    body = [Text(f"  {line}") for line in sqli_findings]
                    summary.append(f"sqlmap reportó {len(sqli_findings)} indicio(s) de SQLi en :{prt}")
            _panel(f"sqlmap · inyección SQL ({url}, intrusivo)", "prueba activa de inyección SQL sobre la web", body, border="red")

    # --- TLS (sslscan) por cada puerto HTTPS ---
    for p, fut in ssl_futs:
        res = _await(f"sslscan {p['port']}", fut)
        if res.error:
            body = _err_body(res)
        else:
            tls = res.value
            body = []
            if tls["protocols"]:
                body.append(Text(f"protocolos habilitados: {', '.join(tls['protocols'])}"))
            if tls["insecure_protocols"]:
                body.append(Text(f"protocolos inseguros: {', '.join(tls['insecure_protocols'])}", style="bold red"))
                body.append(_note("hay versiones de TLS obsoletas habilitadas"))
                summary.append(f"[!] TLS inseguro en {p['port']}: {', '.join(tls['insecure_protocols'])}")
            if tls["weak_ciphers"]:
                body.append(Text(f"cifrados débiles: {len(tls['weak_ciphers'])}", style="red"))
                body.extend(Text(f"  {c}") for c in tls["weak_ciphers"])
            for key, value in tls["cert"].items():
                body.append(Text(f"cert {key}: {value}"))
            if tls["cert"].get("estado") == "CADUCADO":
                summary.append(f"[!] certificado TLS caducado en el puerto {p['port']}")
            if not tls["protocols"] and not tls["cert"]:
                body = [Text("sin handshake TLS (¿requiere SNI/hostname?)", style=GREY)]
        _panel(f"sslscan · TLS (puerto {p['port']})", "protocolos TLS habilitados, cifrados y datos del certificado", body)

    # --- rama SMB ---
    if smb_ports:
        summary.append("SMB accesible (puerto 139/445)")

        if "smbclient" in f:
            res = _await("smbclient", f["smbclient"])
            if res.error:
                body = _err_body(res)
            else:
                shares = res.value
                if not shares:
                    body = [Text("sin recursos visibles sin autenticación", style=GREY)]
                else:
                    t = _table("Tipo", "Nombre", "Comentario")
                    for s in shares:
                        t.add_row(s["type"], s["name"], s["comment"])
                    body = [t]
                    summary.append(f"smbclient listó {len(shares)} recurso(s) compartido(s) sin autenticación")
            _panel("smbclient · recursos SMB", "recursos compartidos accesibles sin autenticación", body)

        if "enum4linux" in f:
            res = _await("enum4linux", f["enum4linux"])
            if res.error:
                body = _err_body(res)
            else:
                e4l_sections = res.value
                if not e4l_sections:
                    body = [Text("sin hallazgos", style=GREY)]
                else:
                    body = []
                    for section, lines in e4l_sections.items():
                        body.append(Text(section, style=PURPLE))
                        body.extend(Text(f"  {line}") for line in lines)
                    if "Usuarios" in e4l_sections:
                        summary.append(f"enum4linux enumeró {len(e4l_sections['Usuarios'])} usuario(s) por SMB")
                    if any("allows sessions" in line for line in e4l_sections.get("Acceso", [])):
                        body.append(_note("permite sesión anónima: se puede enumerar sin credenciales"))
                        summary.append("SMB permite sesión anónima")
            _panel("enum4linux · enumeración SMB", "dominio, sistema, usuarios y recursos vía SMB", body)

        if "nbtscan" in f:
            res = _await("nbtscan", f["nbtscan"])
            if res.error:
                body = _err_body(res)
            else:
                nb = res.value
                if not nb:
                    body = [Text("sin respuesta NetBIOS", style=GREY)]
                else:
                    t = _table("IP", "Nombre", "MAC")
                    for h in nb:
                        t.add_row(h["ip"], h["name"], h["mac"])
                    body = [t]
            _panel("nbtscan · nombres NetBIOS", "nombres NetBIOS del objetivo (137/udp)", body)

        if "netexec" in f:
            res = _await("netexec", f["netexec"])
            if res.error:
                body = _err_body(res)
            else:
                nxc = res.value
                body = []
                if nxc["host"]:
                    body.append(Text("Host", style=PURPLE))
                    body.extend(Text(f"  {line}") for line in nxc["host"])
                if nxc["shares"]:
                    body.append(Text("Recursos", style=PURPLE))
                    body.extend(Text(f"  {line}") for line in nxc["shares"])
                    summary.append(f"netexec listó {len(nxc['shares'])} recurso(s) por sesión nula")
                if any("Null Auth:True" in line for line in nxc["host"]):
                    body.append(_note("sesión nula permitida: enumeración sin credenciales"))
                if not nxc["host"] and not nxc["shares"]:
                    body = [Text("sin datos por sesión nula", style=GREY)]
            _panel("netexec · SMB (sesión nula)", "enumeración SMB sin credenciales (null session)", body)

    # --- SNMP ---
    if "onesixtyone" in f:
        res = _await("onesixtyone", f["onesixtyone"])
        if res.error:
            body = _err_body(res)
        else:
            communities = res.value
            if communities:
                body = []
                for c in communities:
                    body.append(Text(f"comunidad válida: {c['community']}", style="bold yellow"))
                    if c["info"]:
                        body.append(Text(f"  {c['info']}"))
                body.append(_note("comunidad SNMP por defecto activa: cámbiala o desactiva SNMP"))
                summary.append(f"[!] SNMP con comunidad(es) válida(s): {', '.join(c['community'] for c in communities)}")
            else:
                body = [Text("sin comunidades SNMP válidas", style=GREY)]
        _panel("onesixtyone · comunidades SNMP", "prueba nombres de comunidad SNMP habituales (public, private...)", body)

    if "snmp" in f:
        res = _await("snmp", f["snmp"])
        if res.error:
            body = _err_body(res)
        else:
            snmp_findings = res.value
            if not snmp_findings:
                body = [Text("sin respuesta SNMP con 'public'", style=GREY)]
            else:
                body = [Text(f"  {line}") for line in snmp_findings[:40]]
                if len(snmp_findings) > 40:
                    body.append(Text(f"  ... y {len(snmp_findings) - 40} línea(s) más", style=GREY))
                body.append(_note("SNMP con 'public' filtra información del sistema"))
                summary.append(f"[!] SNMP responde con 'public' ({len(snmp_findings)} valor(es))")
        _panel("snmp · enumeración (public)", "datos que expone el objetivo por SNMP con la comunidad 'public'", body)

    # --- hydra (intrusivo, opt-in) ---
    if "hydra" in f:
        res = _await("hydra", f["hydra"])
        if res.error:
            body = _err_body(res)
        else:
            creds = res.value
            if not creds:
                body = [Text("sin credenciales válidas con las wordlists por defecto", style=GREY)]
            else:
                t = _table("Usuario", "Contraseña")
                for c in creds:
                    t.add_row(c["login"], c["password"])
                body = [t, _note("credenciales válidas encontradas: acceso directo al servicio")]
                summary.append(f"hydra encontró {len(creds)} credencial(es) válida(s)")
        _panel(f"hydra · fuerza bruta {args.brute} (intrusivo)", "prueba usuarios/contraseñas habituales contra el servicio", body, border="red")

    # --- Resumen final ---
    summary_body = []
    for line in summary:
        if line.startswith("[!]"):
            summary_body.append(Text(f"• {line[3:].strip()}", style="bold red"))
        else:
            summary_body.append(Text(f"• {line}"))
    _panel("Resumen", "lo esencial de un vistazo (en rojo, lo que conviene mirar primero)", summary_body, border=ORANGE)

    executor.shutdown(wait=True)


if __name__ == "__main__":
    main()

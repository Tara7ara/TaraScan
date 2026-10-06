import argparse
import concurrent.futures
import datetime
import ipaddress
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from tarascan import commands, store, ui
from tarascan.scanners import (
    ai_advisor,
    dns,
    enum4linux,
    feroxbuster,
    ffuf,
    gobuster,
    http_headers,
    hydra,
    net_map,
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

# UI compartida: una sola fuente de verdad para la consola, la paleta y los
# paneles. Lo que cambie en ui.py afecta también al comando principal.
console = ui.console
ORANGE, PURPLE, GREY = ui.ORANGE, ui.PURPLE, ui.GREY

# Cuántas herramientas pueden correr a la vez. Acotado a propósito: lanzar 20
# procesos contra el mismo host a la vez lo satura y puede disparar WAF/límites.
MAX_WORKERS = 8

# Acumulador del informe en Markdown: cada panel añade aquí su versión en texto,
# para poder guardarlo con -o (además de pintarlo en la terminal).
_MD: list[str] = []


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


# Código HTTP coloreado por familia (verde/amarillo/rojo): lo aporta ui.
_status_markup = ui.status


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _get_default_target() -> str | None:
    """Devuelve el objetivo fijado en $T o en ~/.local/state/target si existe."""
    env_t = os.environ.get("T", "").strip()
    if env_t:
        return env_t
    state_file = Path.home() / ".local" / "state" / "target"
    if state_file.is_file():
        try:
            val = state_file.read_text(encoding="utf-8").strip()
            if val:
                return val
        except OSError:
            pass
    return None


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


# Explicación gris (qué mira la herramienta) y nota naranja con flecha: de ui.
_dim = ui.dim
_note = ui.note


def _plain(item) -> str:
    """Texto plano de un renderable (Text o cadena con markup), para el Markdown."""
    if isinstance(item, Text):
        return item.plain
    return Text.from_markup(str(item)).plain


def _table_md(table: Table) -> list[str]:
    """Convierte una tabla de rich en una tabla de Markdown."""
    headers = [_plain(c.header) for c in table.columns]
    rows = ["| " + " | ".join(headers) + " |",
            "| " + " | ".join("---" for _ in headers) + " |"]
    nrows = max((len(c._cells) for c in table.columns), default=0)
    for i in range(nrows):
        cells = []
        for c in table.columns:
            raw = c._cells[i] if i < len(c._cells) else ""
            cells.append(_plain(raw).replace("\n", " ").replace("|", "\\|"))
        rows.append("| " + " | ".join(cells) + " |")
    rows.append("")
    return rows


def _record_md(title: str, desc: str, body: list) -> None:
    """Acumula la versión Markdown de una sección (tablas como tablas, texto libre en bloques de código)."""
    md = [f"## {title}", ""]
    if desc:
        md += [f"*{desc}*", ""]

    text_buf: list[str] = []

    def flush() -> None:
        if text_buf:
            md.append("```text")
            md.extend(text_buf)
            md.append("```")
            md.append("")
            text_buf.clear()

    for item in body:
        if isinstance(item, Table):
            flush()
            md += _table_md(item)
            continue
        text = _plain(item)
        if text.lstrip().startswith("→"):
            # Nota de interpretación: como cita, no dentro del bloque de código.
            flush()
            md += [f"> {text.strip()}", ""]
        else:
            text_buf.append(text)
    flush()

    md.append("")
    _MD.extend(md)


def _panel(title: str, desc: str, body: list, border: str = GREY) -> None:
    """Imprime una sección en su caja (render compartido con ui) y, además, acumula
    su versión Markdown en _MD para poder exportarla con -o."""
    ui.panel(title, desc, body, border=border)
    _record_md(title, desc, body)


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


# Tabla con la cabecera naranja y celdas que envuelven (overflow fold): de ui.
_table = ui.table


def _run_ai(target: str | None = None, kind: str = "target") -> None:
    """Pasa el informe (_MD) al modelo y pinta su análisis. Opt-in con --ai; avisa antes de enviar a un tercero."""
    from rich.markdown import Markdown

    if not ai_advisor.get_key():
        _panel(
            "Análisis con IA",
            "resumen y recomendaciones generados por un modelo",
            [Text("falta la clave: define TARASCAN_AI_KEY con una clave gratuita de "
                  "build.nvidia.com. Mira el README.", style="bold red")],
            border="red",
        )
        return

    console.print(
        f"[{GREY}]El informe (IPs, servicios, versiones) se envía al endpoint de IA "
        f"configurado. Úsalo solo con datos que puedas compartir.[/]"
    )
    report = "\n".join(_MD)
    try:
        with console.status(f"[{ORANGE}]pensando[/][{GREY}]… (consultando al modelo)[/]", spinner="dots"):
            answer, model_used = ai_advisor.analyze(report, target, kind)
    except ai_advisor.AIError as exc:
        _panel(
            "Análisis con IA",
            "resumen y recomendaciones generados por un modelo",
            [Text(str(exc), style="bold red")],
            border="red",
        )
        return

    console.print(
        Panel(
            Markdown(answer),
            title=f"[bold {ORANGE}]Análisis con IA[/] [{GREY}]({escape(model_used)})[/]",
            title_align="left",
            border_style=PURPLE,
            padding=(0, 1),
        )
    )
    # En el .md va el Markdown tal cual (es Markdown ya), no como bloque de código.
    _MD.append(f"## Análisis con IA ({model_used})")
    _MD.append("")
    _MD.append(answer)
    _MD.append("")

    # Guarda el análisis en la persistencia para que `report` lo incluya.
    if kind == "target" and target:
        try:
            data = store.load_target(target)
            data["ai"] = {"model": model_used, "text": answer}
            store.save_target(data)
        except Exception:  # noqa: BLE001
            pass


# Secciones de _MD que no son una herramienta de recon (resúmenes, IA): fuera.
_SCAN_SKIP = ("Resumen", "Análisis con IA", "Copiloto")

# "Plugins" de whatweb que son metadatos, no tecnología real: no van a `tech`.
_WHATWEB_NOISE = {
    "Country", "IP", "Title", "Script", "MetaGenerator", "UncommonHeaders",
    "X-Powered-By", "HTML5", "Email", "Cookies", "PasswordField", "Frame",
    "RedirectLocation", "Via-Proxy", "Strict-Transport-Security", "HTTPServer",
}


def _scans_from_md() -> dict:
    """Deriva de las cabeceras '## <herramienta · descripción>' de _MD qué
    herramientas corrieron, para que `report` liste la fase ejecutada."""
    scans: dict = {}
    for line in _MD:
        if not line.startswith("## "):
            continue
        title = line[3:].strip()
        if any(title.startswith(skip) for skip in _SCAN_SKIP):
            continue
        if " · " in title:
            tool, desc = title.split(" · ", 1)
        else:
            tool, desc = title, ""
        scans.setdefault(tool.strip(), {"resumen": desc.strip()})
    return scans


# Servicio probable por número de puerto, para enriquecer lo que da el mapa de red.
_PORT_SERVICE = {
    "21": "ftp", "22": "ssh", "23": "telnet", "25": "smtp", "53": "dns",
    "80": "http", "110": "pop3", "111": "rpcbind", "135": "msrpc",
    "139": "netbios-ssn", "143": "imap", "161": "snmp", "389": "ldap",
    "443": "https", "445": "microsoft-ds", "993": "imaps", "995": "pop3s",
    "1433": "ms-sql", "3306": "mysql", "3389": "ms-wbt-server", "5432": "postgresql",
    "5900": "vnc", "6379": "redis", "8080": "http-proxy", "8443": "https-alt",
}


def _persist_net_devices(devices: list[dict]) -> None:
    """Guarda los puertos de cada host del mapa en su propio JSON de objetivo."""
    for d in devices:
        ip = d.get("ip")
        raw = d.get("ports", "")
        if not ip or raw in ("", "-"):
            continue
        ports = []
        for tok in raw.split(","):
            num = tok.strip()
            if num.isdigit():
                ports.append({"port": num, "service": _PORT_SERVICE.get(num, ""), "version": ""})
        if ports:
            try:
                store.record_scan(ip, ports=ports)
            except Exception:  # noqa: BLE001 - comodidad, no debe tumbar el mapa
                pass


def _cached_ports(target: str) -> dict | None:
    """Devuelve {ports, age} si hay puertos guardados del objetivo lo bastante
    recientes como para no re-escanear. TTL en minutos vía
    TARASCAN_CACHE_TTL (30 por defecto; 0 desactiva la caché). None si no sirve."""
    try:
        ttl_min = int(os.environ.get("TARASCAN_CACHE_TTL", "30") or 30)
    except ValueError:
        ttl_min = 30
    if ttl_min <= 0:
        return None
    try:
        data = store.load_target(target)
    except Exception:  # noqa: BLE001
        return None
    ports, updated = data.get("ports") or [], data.get("updated")
    if not ports or not updated:
        return None
    try:
        age = datetime.datetime.now() - datetime.datetime.fromisoformat(updated)
    except (ValueError, TypeError):
        return None
    if age > datetime.timedelta(minutes=ttl_min):
        return None
    norm = [{"port": p.get("port"), "proto": p.get("proto", "tcp"),
             "service": p.get("service", "") or "?", "version": p.get("version", "")}
            for p in ports if p.get("port")]
    mins = int(age.total_seconds() // 60)
    return {"ports": norm, "age": f"hace {mins}m" if mins else "hace <1m"}


def _persist_recon(target: str, ports: list[dict], summary: list[str], tech: list[str] | None = None) -> None:
    """Guarda puertos, hallazgos, tecnologías y herramientas ejecutadas del recon
    para que `report` y las fases posteriores tengan el histórico completo."""
    findings = [line.strip() for line in summary]  # conserva el marcador [!] de lo crítico
    clean_ports = [
        {"port": p.get("port"), "service": p.get("service"), "version": p.get("version", "")}
        for p in ports
    ]
    try:
        store.record_scan(target, ports=clean_ports, findings=findings,
                          tech=tech or None, scans=_scans_from_md())
        store.add_snapshot(target, clean_ports, tech)
        store.set_active_target(target)
    except Exception:  # noqa: BLE001 - la persistencia es una comodidad, no debe tumbar nada
        pass


# Flags de tarascan que el modo guiado puede proponer y ejecutar. Lista blanca:
# nada fuera de aquí se lanza, por si el modelo se inventa algo.
_GUIDED_ALLOWED = {"--full", "--deep", "--sqli", "--brute", "--only", "--skip"}

# Flags que el guiado de RED puede proponer: solo recon, nada intrusivo (no se
# lanza fuerza bruta/sqlmap en masa contra toda una subred desde un barrido).
_GUIDED_NET_ALLOWED = {"--full", "--deep"}

# Subcomandos que no necesitan objetivo (el copiloto los propone como utilidad).
_GUIDED_UTILS = {"hash", "decode", "jwt", "shell", "serve", "pivot", "gtfobins"}

# Subcomandos que no apuntan al objetivo por IP (su argumento es un producto, un
# hash, etc.), así que no se les exige que el objetivo aparezca en los argumentos.
_GUIDED_NO_TARGET_CHECK = _GUIDED_UTILS | {"cve"}


def _norm_cmd(cmd: str) -> str:
    """Clave normalizada de un comando para deduplicar: espacios colapsados, en
    minúsculas y sin la barra final de las URLs (web http://x y web http://x/ = lo mismo)."""
    toks = [t.rstrip("/") if t.startswith(("http://", "https://")) else t for t in cmd.split()]
    return " ".join(toks).lower()


def _validate_guided_cmd(cmd: str, *, target: str | None = None,
                         net_ips: set | None = None, allow_flags: set) -> str | None:
    """Valida una propuesta del copiloto (subcomando o recon con flag de la lista blanca).
    Devuelve el comando normalizado, o None si no es tarascan reconocible."""
    import shlex

    try:
        parts = shlex.split(cmd)
    except ValueError:
        return None
    if len(parts) < 2 or parts[0] != "tarascan":
        return None

    head = parts[1]
    # Forma b) subcomando conocido.
    if head in commands.REGISTRY:
        # Utilidades y cve no apuntan al objetivo por IP (su argumento es un hash,
        # un producto+versión, etc.): no exigimos que el objetivo esté en los args.
        if head in _GUIDED_NO_TARGET_CHECK:
            return " ".join(parts)
        rest = parts[2:]
        if net_ips is not None:
            return " ".join(parts) if any(p in net_ips for p in rest) else None
        if target is not None:
            return " ".join(parts) if any(target in p for p in rest) else None
        return " ".join(parts)

    # Forma a) recon con flags: 'tarascan <objetivo> [flags]', en CUALQUIER orden.
    # Recogemos las flags de la lista blanca con su valor (--brute ssh, --only a,b)
    # y reconstruimos siempre como 'tarascan <objetivo> <flags>', para no perder la
    # flag si el modelo la puso antes del objetivo.
    _FLAGS_CON_VALOR = {"--brute", "--only", "--skip"}
    toks = parts[1:]
    flags_out: list[str] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.startswith("--"):
            if t not in allow_flags:
                return None  # flag fuera de la lista blanca: se descarta entero
            flags_out.append(t)
            if t in _FLAGS_CON_VALOR and i + 1 < len(toks) and not toks[i + 1].startswith("--"):
                flags_out.append(toks[i + 1])
                i += 2
                continue
        i += 1

    if net_ips is not None:
        # En modo red, el recon completo de un host de la tabla SÍ es un paso
        # válido (con o sin flag); el objetivo es una IP de la tabla.
        ips = [t for t in toks if t in net_ips]
        if not ips:
            return None
        return f"tarascan {ips[0]} {' '.join(flags_out)}".strip()
    if not flags_out:  # en modo objetivo, recon sin flag no aporta (ya se hizo)
        return None
    return f"tarascan {target} {' '.join(flags_out)}".strip()


def _guided_ask(report_text: str, kind_label: str, target: str, kind: str, ya_hechos=None):
    """Pide al copiloto el análisis + acciones sobre el informe que se le pasa.
    Devuelve (resumen, acciones, modelo) o None si no hay clave / falla la IA."""
    from rich.markdown import Markdown

    if not ai_advisor.get_key():
        _panel("Copiloto IA", "modo guiado", [Text(
            "falta la clave: define TARASCAN_AI_KEY (build.nvidia.com). Mira el README.",
            style="bold red")], border="red")
        return None

    try:
        with console.status(f"[{ORANGE}]pensando[/][{GREY}]… (el copiloto analiza {kind_label})[/]", spinner="dots"):
            resumen, acciones, model_used = ai_advisor.suggest_actions(
                report_text, target, kind=kind, already_run=ya_hechos)
    except ai_advisor.AIError as exc:
        _panel("Copiloto IA", "modo guiado", [Text(str(exc), style="bold red")], border="red")
        return None

    if resumen:
        console.print(Panel(Markdown(resumen),
                            title=f"[bold {ORANGE}]Copiloto · análisis[/] [{GREY}]({escape(model_used)})[/]",
                            title_align="left", border_style=PURPLE, padding=(0, 1)))
    return resumen, acciones, model_used


def _guided_menu_pick(validas: list[dict]) -> list[dict] | None:
    """Pinta el menú y devuelve la selección (o None para salir/cancelar)."""
    body = []
    for i, a in enumerate(validas, 1):
        body.append(Text.from_markup(f"[bold {ORANGE}][{i}][/] [{PURPLE}]{escape(a['comando'])}[/]"))
        if a["motivo"]:
            body.append(Text(f"    {a['motivo']}", style=GREY))
    _panel("Copiloto · siguientes pasos", "elige qué lanzar; al terminar reanaliza y propone más", body, border=ORANGE)

    try:
        choice = console.input(
            f"[{ORANGE}]Qué lanzo[/] [{GREY}]([1-{len(validas)}] separados por espacio, "
            f"a=todas, q=salir):[/] "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print(f"\n[{GREY}]cancelado[/]")
        return None

    if choice in ("q", ""):
        return None
    if choice == "a":
        return validas
    idx = {int(n) for n in re.findall(r"\d+", choice)}
    seleccion = [a for i, a in enumerate(validas, 1) if i in idx]
    if not seleccion:
        console.print(f"[{GREY}]nada seleccionado[/]")
        return None
    return seleccion


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")


def _strip_ansi(text: str) -> str:
    """Quita los códigos de color/escape ANSI, para la copia que va al informe y a la IA."""
    return _ANSI_RE.sub("", text)


def _exec_capture_pipe(argv: list[str], cmd: str) -> str:
    """Respaldo sin pseudo-terminal (SO sin pty): captura por tubería, sin spinner."""
    import shutil
    if argv and argv[0] == "tarascan" and not shutil.which("tarascan"):
        argv = [sys.executable, "-m", "tarascan.cli", *argv[1:]]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except (FileNotFoundError, OSError) as exc:
        Console(stderr=True, style="bold red").print(
            f"no se pudo ejecutar '{cmd}': {exc}", markup=False, highlight=False)
        return f"(no se pudo ejecutar: {exc})"
    buf: list[str] = []
    if proc.stdout:
        for line in proc.stdout:
            sys.stdout.write(line)
            buf.append(line)
    proc.wait()
    sys.stdout.flush()
    return _strip_ansi("".join(buf))[-6000:]


def _exec_capture(cmd: str) -> str:
    """Lanza un comando de tarascan mostrándolo en vivo y devolviendo su salida
    (recortada, sin ANSI) para realimentar al copiloto en la siguiente ronda.

    Usa una pseudo-terminal (pty): así el tarascan hijo cree que tiene terminal y
    mantiene su spinner, sus colores y el ancho de la sesión (con una tubería rich
    lo desactivaba todo y las cajas se iban a 80 columnas)."""
    import shlex
    import shutil

    console.rule(f"[bold {ORANGE}]ejecutando[/] [{PURPLE}]{escape(cmd)}[/]", style=GREY)
    try:
        argv = shlex.split(cmd)
    except ValueError as exc:
        Console(stderr=True, style="bold red").print(
            f"comando inválido '{cmd}': {exc}", markup=False, highlight=False)
        return f"(comando inválido: {exc})"

    if argv and argv[0] == "tarascan" and not shutil.which("tarascan"):
        argv = [sys.executable, "-m", "tarascan.cli", *argv[1:]]

    try:
        import pty
    except ImportError:
        return _exec_capture_pipe(argv, cmd)

    raw = bytearray()

    def _read(fd):
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            return b""
        raw.extend(chunk)
        return chunk  # pty.spawn lo reeenvía a la terminal real (eco en vivo)

    # Forzamos el ancho de la sesión en el hijo (rich respeta COLUMNS).
    old_cols = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = str(console.size.width)
    try:
        pty.spawn(argv, _read)
    except (FileNotFoundError, OSError) as exc:
        Console(stderr=True, style="bold red").print(
            f"no se pudo ejecutar '{cmd}': {exc}", markup=False, highlight=False)
        return f"(no se pudo ejecutar: {exc})"
    finally:
        if old_cols is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = old_cols

    sys.stdout.flush()
    return _strip_ansi(raw.decode("utf-8", "replace"))[-6000:]


def _guided_loop(report0: str, target: str, kind: str, validate, auto: bool = False) -> None:
    """Copiloto iterativo: analiza -> propone -> ejecuta -> reanaliza, hasta salir o agotar rondas.
    auto=True: manos libres, ejecuta la mejor sugerencia de cada ronda sin preguntar."""
    try:
        max_rondas = int(os.environ.get("TARASCAN_GUIDED_ROUNDS", "5") or 5)
    except ValueError:
        max_rondas = 5

    if auto:
        console.print(Panel(
            Text("Modo manos libres: el copiloto ejecutará sus propias sugerencias "
                 f"sin preguntar, hasta {max_rondas} rondas. Solo lanza comandos de "
                 "tarascan. Ctrl-C para cortar.", style=ORANGE),
            title=f"[bold {ORANGE}]Copiloto --auto[/]", title_align="left",
            border_style="red", padding=(0, 1)))
    else:
        console.print(
            f"[{GREY}]El informe (IPs, servicios, versiones) se envía al endpoint de IA "
            f"para proponer los siguientes pasos. Copiloto iterativo: tras ejecutar, reanaliza.[/]"
        )
    report_acc = report0
    ejecutados: set[str] = set()       # claves normalizadas, para no repetir
    hechos: list[str] = []             # comandos tal cual, para avisar a la IA

    try:
        for ronda in range(1, max_rondas + 1):
            etiqueta = ("el recon" if kind == "target" else "la red") if ronda == 1 else "los nuevos resultados"
            got = _guided_ask(report_acc, etiqueta, target, kind, ya_hechos=hechos)
            if got is None:
                return
            _, acciones, _ = got

            validas: list[dict] = []
            vistos: set[str] = set()
            for a in acciones:
                norm = validate(a.get("comando") or "")
                if not norm:
                    continue
                clave = _norm_cmd(norm)
                if clave in ejecutados or clave in vistos:
                    continue  # ya ejecutado o repetido en esta misma ronda
                vistos.add(clave)
                validas.append({"comando": norm, "motivo": a.get("motivo", "")})
            if not validas:
                _panel("Copiloto · siguientes pasos", "",
                       [Text("el copiloto no ve nada nuevo que accionar. Fin de la sesión.", style=GREY)], border=ORANGE)
                return

            if auto:
                # Manos libres: la mejor sugerencia (la primera, ya ordenada por el modelo).
                seleccion = [validas[0]]
                _panel("Copiloto · siguientes pasos (auto)", "lanzando automáticamente la mejor sugerencia", [
                    Text.from_markup(f"[bold {ORANGE}]→[/] [{PURPLE}]{escape(validas[0]['comando'])}[/]"),
                    *( [Text(f"   {validas[0]['motivo']}", style=GREY)] if validas[0]["motivo"] else [] ),
                ], border=ORANGE)
            else:
                seleccion = _guided_menu_pick(validas)
                if not seleccion:
                    return

            for a in seleccion:
                ejecutados.add(_norm_cmd(a["comando"]))
                hechos.append(a["comando"])
                out = _exec_capture(a["comando"])
                report_acc += f"\n\n## salida de `{a['comando']}`\n{out}"
                # Al informe exportable (-o): lo que lanza el copiloto también cuenta.
                _MD.extend([f"## copiloto · `{a['comando']}`", "", "```", out.strip(), "```", ""])

            # Mantén el contexto acotado: esencia del recon inicial + lo más reciente.
            if len(report_acc) > 20000:
                report_acc = report0[:4000] + "\n\n[...]\n\n" + report_acc[-16000:]
            console.print(f"\n[{GREY}]— el copiloto reanaliza con los resultados nuevos (ronda {ronda + 1}) —[/]\n")
    except KeyboardInterrupt:
        console.print(f"\n[{GREY}]copiloto detenido por el usuario.[/]")
        return

    console.print(f"[{GREY}]fin del copiloto (tope de {max_rondas} rondas). Relanza --guided para seguir.[/]")


def _run_guided(target: str, args) -> None:
    """Copiloto IA iterativo sobre el recon de un objetivo."""
    _guided_loop(
        "\n".join(_MD), target, "target",
        lambda c: _validate_guided_cmd(c, target=target, allow_flags=_GUIDED_ALLOWED),
        auto=getattr(args, "auto", False),
    )


def _run_guided_net(cidr: str, devices: list[dict], auto: bool = False) -> None:
    """Copiloto IA iterativo sobre un mapa de red."""
    ips = {d.get("ip") for d in devices}
    _guided_loop(
        "\n".join(_MD), cidr, "net",
        lambda c: _validate_guided_cmd(c, net_ips=ips, allow_flags=_GUIDED_NET_ALLOWED),
        auto=auto,
    )


def _run_net_map(net_arg: str, output_path: str | None, use_ai: bool = False,
                 use_guided: bool = False, use_auto: bool = False) -> None:
    """Modo de descubrimiento de red: mapea hosts activos, MACs y fabricantes."""
    local_info = net_map.detect_local_network()

    if net_arg in ("auto", "", None):
        if not local_info or not local_info.get("cidr"):
            error = Console(stderr=True, style="bold red")
            error.print("no se pudo detectar la subred local automáticamente; especifica una (p.ej. --net 192.168.1.0/24)", highlight=False)
            sys.exit(1)
        cidr = local_info["cidr"]
    else:
        cidr = net_arg

    console.print()
    console.rule(f"[bold {ORANGE}]tarascan[/] · mapa de red [{PURPLE}]{escape(cidr)}[/]", style=GREY)
    console.print()

    if local_info and local_info.get("interface"):
        gw_txt = local_info.get("gateway") or "-"
        console.print(
            f"  [{GREY}]interfaz:[/] {local_info['interface']}   "
            f"[{GREY}]tu IP:[/] {local_info.get('local_ip', '-')}   "
            f"[{GREY}]gateway:[/] {gw_txt}\n"
        )

    with console.status(f"[{ORANGE}]escaneando subred[/][{GREY}]… ({cidr})[/]", spinner="dots"):
        devices = net_map.scan(cidr, local_info)

    if not devices:
        _panel("Dispositivos en la red", "barrido de hosts activos en la subred", [Text("sin dispositivos detectados", style=GREY)], border=ORANGE)
    else:
        t = _table("IP", "Hostname", "S.O. / Versión", "Puertos", "MAC", "Fabricante", "Rol")
        for d in devices:
            role_style = "bold yellow" if "gateway" in d["role"] else "bold green" if "este equipo" in d["role"] else ""
            t.add_row(
                d["ip"],
                d["hostname"] if d["hostname"] != "-" else Text("-", style=GREY),
                d["os"] if d["os"] != "-" else Text("-", style=GREY),
                Text(d["ports"], style=ORANGE) if d["ports"] != "-" else Text("-", style=GREY),
                d["mac"],
                d["vendor"] if d["vendor"] != "-" else Text("-", style=GREY),
                Text(d["role"], style=role_style) if d["role"] else "",
            )
        _panel(
            "Dispositivos en la red",
            f"hosts activos en {cidr} (ping sweep + RDP/SMB NTLM + banners + ARP)",
            [t],
            border=ORANGE,
        )

    os_identified = sum(1 for d in devices if d.get("os") and d["os"] != "-")
    names_identified = sum(1 for d in devices if d.get("hostname") and d["hostname"] != "-")
    summary_body = [
        Text(f"• {len(devices)} dispositivo(s) activo(s) en {cidr}"),
        Text(f"• {names_identified} nombre(s) de equipo identificado(s)"),
        Text(f"• {os_identified} sistema(s) operativo(s) perfilado(s)"),
    ]
    if local_info and local_info.get("gateway"):
        summary_body.append(Text(f"• gateway: {local_info['gateway']}"))
    _panel("Resumen de red", "lo esencial del segmento", summary_body, border=ORANGE)

    # Persiste cada host del mapa para que report/audit/cve funcionen por IP sin
    # re-escanear (sin pisar un recon completo previo, gracias al merge de store).
    _persist_net_devices(devices)

    if use_guided:
        _run_guided_net(cidr, devices, auto=use_auto)
    elif use_ai:
        _run_ai(cidr, kind="net")

    if output_path is not None:
        path = _resolve_output_path(output_path, f"net-{cidr}")
        header = (
            f"# tarascan · mapa de red {cidr}\n\n"
            f"_{datetime.datetime.now():%Y-%m-%d %H:%M}_\n\n"
        )
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(header + "\n".join(_MD), encoding="utf-8")
            console.print(f"\n[{ORANGE}]Informe guardado en[/] {escape(str(path))}")
        except OSError as exc:
            error = Console(stderr=True, style="bold red")
            error.print(f"no se pudo guardar el informe en {path}: {exc}", markup=False, highlight=False)


def main() -> None:
    # Despacho de subcomandos (hash, shell, osint, report...). Si el primer
    # argumento es uno de ellos, va por su propia ruta y no por el recon.
    argv = sys.argv[1:]
    if argv and commands.is_command(argv[0]):
        sys.exit(commands.dispatch(argv[0], argv[1:]))

    parser = argparse.ArgumentParser(
        prog="tarascan",
        description="Recon de un objetivo encadenando herramientas ya instaladas, salida unificada por terminal.",
        epilog="Subcomandos: " + ", ".join(name for name, _ in commands.help_lines())
        + ". Usa 'tarascan <subcomando> -h' para su ayuda.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="dominio o IP a escanear (por defecto usa $T o set-target si está fijado)",
    )
    parser.add_argument(
        "-n",
        "--net",
        "--map",
        dest="net",
        nargs="?",
        const="auto",
        metavar="CIDR",
        help="escanea la red y lista dispositivos activos con IP, MAC y fabricante (por defecto tu subred actual)",
    )
    parser.add_argument(
        "-f", "--full",
        action="store_true",
        help="nmap escanea los 65535 puertos (-p-) en vez del top-100 (más lento)",
    )
    parser.add_argument(
        "-r",
        "--fresh",
        action="store_true",
        help="ignora los puertos en caché y re-escanea con nmap desde cero",
    )
    parser.add_argument(
        "-y",
        "--only",
        metavar="LISTA",
        help="ejecuta SOLO estas herramientas (coma: p.ej. nmap,nuclei,smbclient)",
    )
    parser.add_argument(
        "-k",
        "--skip",
        metavar="LISTA",
        help="omite estas herramientas (coma: p.ej. nuclei,nikto)",
    )
    parser.add_argument(
        "-s",
        "--sqli",
        action="store_true",
        help="lanza sqlmap contra la web detectada (intrusivo, solo objetivos autorizados)",
    )
    parser.add_argument(
        "-b",
        "--brute",
        metavar="SERVICIO",
        help="lanza hydra contra el objetivo para el servicio dado (ssh, ftp, http-get...); intrusivo",
    )
    parser.add_argument(
        "-d",
        "--deep",
        action="store_true",
        help="descubrimiento de contenido recursivo con feroxbuster (más lento que gobuster)",
    )
    parser.add_argument(
        "-i",
        "--ai",
        action="store_true",
        help="al terminar, pide a un modelo (NVIDIA gratis) un resumen, lo crítico "
             "y comandos sugeridos; requiere TARASCAN_AI_KEY (ver README)",
    )
    parser.add_argument(
        "-g", "--guided",
        action="store_true",
        help="copiloto IA: analiza el recon (o el mapa con --net) y propone el "
             "siguiente paso con cualquier comando de tarascan (flags o subcomandos "
             "como audit/web/cve/report) en un menú interactivo; requiere TARASCAN_AI_KEY",
    )
    parser.add_argument(
        "-a",
        "--auto",
        action="store_true",
        help="copiloto manos libres: ejecuta solo la mejor sugerencia en cada ronda "
             "sin preguntar, encadenando pasos hasta agotar el tope (implica --guided)",
    )
    parser.add_argument(
        "-o", "--output",
        nargs="?",
        const="",
        metavar="RUTA",
        help="guarda el informe en Markdown; sin valor, en el directorio actual; "
             "con RUTA (fichero o carpeta), ahí",
    )
    args = parser.parse_args()
    if args.auto:
        args.guided = True  # el modo manos libres es una variante del copiloto

    # Modo mapa de red (--net, --map o CIDR posicional)
    if args.net is not None:
        _run_net_map(args.net, args.output, args.ai, args.guided, args.auto)
        return
    if args.target and "/" in args.target:
        try:
            net_obj = ipaddress.ip_network(args.target.strip(), strict=False)
            if net_obj.prefixlen < 32:
                _run_net_map(str(net_obj), args.output, args.ai, args.guided, args.auto)
                return
        except ValueError:
            pass

    target = args.target.strip() if args.target else None
    using_default = False
    if not target:
        target = _get_default_target()
        using_default = bool(target)

    if not target:
        parser.error("falta el objetivo: pasa una IP/dominio, usa --net o fija uno con set-target / $T")

    # Selección de herramientas. nmap es la base y siempre corre.
    only = {x.strip() for x in args.only.split(",")} if args.only else None
    skip = {x.strip() for x in args.skip.split(",")} if args.skip else set()

    def on(name: str) -> bool:
        if name == "nmap":
            return True
        return (only is None or name in only) and name not in skip

    console.print()
    origin_note = f" [{GREY}]($T)[/]" if using_default else ""
    console.rule(f"[bold {ORANGE}]tarascan[/] · recon sobre [{PURPLE}]{escape(target)}[/]{origin_note}", style=GREY)
    console.print()
    summary: list[str] = []
    tech: list[str] = []  # tecnologías web detectadas (whatweb/wpscan), para el report

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
    # Caché de puertos: si hay un escaneo reciente y no se pide
    # --fresh ni --full (que exige escaneo completo nuevo), reutilizamos nmap.
    ports_cache = None if (args.fresh or args.full) else _cached_ports(target)
    from_cache = False
    full_fut = None  # con --full: el barrido -p- que corre en paralelo (se recoge al final)

    if ports_cache is not None:
        ports = ports_cache["ports"]
        from_cache = True
        console.print(
            f"[{GREY}]puertos reutilizados de la caché ({ports_cache['age']}); "
            f"--fresh para re-escanear con nmap.[/]"
        )
    else:
        if args.full:
            # Pasada rápida (top-100) para ARRANCAR YA todo el recon, y el barrido
            # completo -p- en paralelo: así web/SMB/exploits no esperan 20 min a que
            # nmap recorra los 65535 puertos. Los extras se muestran al final.
            f["nmap"] = executor.submit(_call, "nmap", nmap.scan, target, False)
            full_fut = executor.submit(_call, "nmap", nmap.scan, target, True)
            nota = "top-100 para arrancar; barrido completo -p- en paralelo"
        else:
            f["nmap"] = executor.submit(_call, "nmap", nmap.scan, target, False)
            nota = "top-100; recon inicial en paralelo"
        with console.status(f"[{ORANGE}]lanzando nmap[/][{GREY}]… ({nota})[/]", spinner="dots"):
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
            t.add_row(p["port"], p.get("proto", "tcp"), p["service"], p.get("version", "") or "?")
        body = [t]
        if from_cache:
            body.append(_note(f"puertos de la caché ({ports_cache['age']}); usa --fresh para re-escanear."))
    titulo = "nmap · puertos (caché)" if from_cache else "nmap · puertos abiertos"
    _panel(titulo, "qué servicios y versiones expone el objetivo", body)
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
                for name in info["plugins"]:
                    if name not in _WHATWEB_NOISE and name not in tech:
                        tech.append(name)
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

    # --- Barrido completo (-p-): corrió en paralelo; mostramos lo que añade ---
    if full_fut is not None:
        with console.status(f"[{ORANGE}]barrido completo[/][{GREY}]… (nmap -p-, 65535 puertos; el recon de arriba ya está hecho)[/]", spinner="dots"):
            full_res = full_fut.result()
        if full_res.error:
            _panel("nmap · barrido completo (-p-)", "escaneo de los 65535 puertos", _err_body(full_res), border="red")
        else:
            full_ports = full_res.value

            def _pk(p: dict) -> int:
                try:
                    return int(p.get("port"))
                except (ValueError, TypeError):
                    return 0

            t = _table("Puerto", "Proto", "Servicio", "Versión")
            for p in sorted(full_ports, key=_pk):
                t.add_row(p["port"], p.get("proto", "tcp"), p["service"], p.get("version", "") or "?")
            body = [t]
            seen = {p["port"] for p in ports}
            extra = [p for p in full_ports if p["port"] not in seen]
            if extra:
                nums = ", ".join(p["port"] for p in sorted(extra, key=_pk))
                body.append(_note(f"{len(extra)} puerto(s) fuera del top-100: {nums}. Audítalos/escánealos si interesan."))
                summary.append(f"[!] --full halló {len(extra)} puerto(s) extra fuera del top-100: {nums}")
                # searchsploit sobre los extras con versión (acotado, en paralelo).
                ss = []
                for p in extra[:20]:
                    term = _search_term(p)
                    if term:
                        ss.append((p["port"], executor.submit(_call, "searchsploit", searchsploit.scan, term)))
                hits = []
                for port, fut in ss:
                    r = _await(f"searchsploit {port}", fut)
                    if not r.error and r.value:
                        hits.append(f"{port} ({len(r.value)})")
                if hits:
                    body.append(_note("exploits públicos en los puertos extra: " + ", ".join(hits)
                                      + " — confírmalos con 'tarascan cve <producto> <versión>'."))
            else:
                body.append(Text("sin puertos nuevos fuera del top-100", style=GREY))
            _panel("nmap · barrido completo (65535 puertos)", "lo que el -p- añade sobre el recon del top-100", body)
            # A partir de aquí trabajamos con la lista completa (persistencia, report).
            ports = full_ports

    # --- Resumen final ---
    summary_body = []
    for line in summary:
        if line.startswith("[!]"):
            summary_body.append(Text(f"• {line[3:].strip()}", style="bold red"))
        else:
            summary_body.append(Text(f"• {line}"))
    _panel("Resumen", "lo esencial de un vistazo (en rojo, lo que conviene mirar primero)", summary_body, border=ORANGE)

    executor.shutdown(wait=True)

    # --- Persistencia: guarda lo descubierto para report/fases posteriores ---
    _persist_recon(target, ports, summary, tech)

    # --- Modo guiado (copiloto IA): analiza y propone flags en un menú ---
    if args.guided:
        _run_guided(target, args)
        if args.output is None:
            return

    # --- Análisis con IA (opt-in con --ai; --guided ya lo cubre) ---
    if args.ai and not args.guided:
        _run_ai(target)

    # --- Exportar a Markdown si se pidió con -o/--output ---
    if args.output is not None:
        path = _resolve_output_path(args.output, target)
        header = (
            f"# tarascan · recon sobre {target}\n\n"
            f"_{datetime.datetime.now():%Y-%m-%d %H:%M}_\n\n"
        )
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(header + "\n".join(_MD), encoding="utf-8")
            console.print(f"\n[{ORANGE}]Informe guardado en[/] {escape(str(path))}")
        except OSError as exc:
            error = Console(stderr=True, style="bold red")
            error.print(f"no se pudo guardar el informe en {path}: {exc}", markup=False, highlight=False)


def _resolve_output_path(value: str, target: str) -> str:
    """Decide dónde guardar el .md: cwd por defecto, o la RUTA dada (fichero o carpeta)."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    fname = f"tarascan-{safe}-{datetime.datetime.now():%Y%m%d-%H%M%S}.md"
    if not value:  # -o sin valor: carpeta report/ del workspace activo, o el cwd
        ws = store.get_active_workspace()
        if ws:
            return os.path.join(ws, "report", fname)
        return os.path.join(os.getcwd(), fname)
    if os.path.isdir(value) or value.endswith(os.sep):  # carpeta: nombre automático dentro
        return os.path.join(value, fname)
    return value  # ruta de fichero concreta


if __name__ == "__main__":
    main()

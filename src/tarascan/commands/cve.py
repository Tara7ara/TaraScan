"""Exploits conocidos de un banner vía searchsploit (exploit-db local)."""

import argparse
import subprocess

import re

from tarascan import store, ui
from tarascan.scanners import searchsploit


def _term_from_port(p: dict) -> str:
    """Término de búsqueda a partir de un puerto guardado (producto + versión)."""
    version = (p.get("version") or "").strip()
    if version:
        product, numeric = [], ""
        for token in version.split():
            if re.match(r"^\d", token):
                numeric = re.match(r"^[\d.]+", token).group(0).rstrip(".")
                break
            product.append(token)
        if product and numeric:
            return f"{' '.join(product)} {numeric}"
        return " ".join(version.split()[:3])
    service = (p.get("service") or "").strip()
    return service if service and service != "?" else ""


def _render(term: str, findings: list[dict]) -> None:
    if not findings:
        ui.panel(f"Exploits · {term}", "sin resultados en exploit-db local", [
            ui.Text("nada en searchsploit para ese término.", style=ui.GREY),
            ui.note("prueba un término más corto, y verifica en https://nvd.nist.gov o 'searchsploit -w'."),
        ])
        return
    t = ui.table("EDB-ID", "Tipo", "Título")
    for f in findings[:50]:
        t.add_row(ui.Text(f["edb"], style=ui.ORANGE), f["type"], f["title"])
    extra = [ui.Text(f"... y {len(findings) - 50} más", style=ui.GREY)] if len(findings) > 50 else []
    ui.panel(f"Exploits · {term}", f"{len(findings)} resultado(s) en exploit-db",
             [t, *extra, ui.note("mira: searchsploit -x <EDB-ID>  ·  copia: searchsploit -m <EDB-ID>")])


def cmd_cve(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="tarascan cve",
        description="exploits conocidos de un software/versión (searchsploit)",
    )
    p.add_argument("software", nargs="*", help="producto y versión, p.ej. vsftpd 2.3.4 (sin args: usa los servicios del objetivo activo)")
    p.add_argument("-t", "--target", help="objetivo cuyos servicios guardados buscar (por defecto, el activo)")
    args = p.parse_args(argv)

    # Modo 1: término explícito.
    if args.software:
        terms = [" ".join(args.software).strip()]
        ui.rule(f"exploits conocidos · [{ui.PURPLE}]{ui.escape(terms[0])}[/]")
    else:
        # Modo 2: sin término -> de los servicios guardados del objetivo.
        target = args.target or store.get_active_target()
        if not target:
            ui.error("pasa un producto (tarascan cve vsftpd 2.3.4) o escanea un objetivo antes (se guardan sus servicios)")
            return 1
        data = store.load_target(target)
        terms = sorted({t for t in (_term_from_port(p) for p in data.get("ports", [])) if t})
        if not terms:
            ui.error(f"no hay servicios guardados de '{target}' con producto/versión. Escanéalo: tarascan {target}")
            return 1
        ui.rule(f"exploits conocidos · servicios de [{ui.PURPLE}]{ui.escape(target)}[/]")
        ui.console.print(f"[{ui.GREY}]buscando: {', '.join(terms)}[/]\n")

    for term in terms:
        try:
            with ui.console.status(f"[{ui.ORANGE}]searchsploit[/][{ui.GREY}]… {ui.escape(term)}[/]", spinner="dots"):
                findings = searchsploit.scan(term)
        except FileNotFoundError:
            ui.error("searchsploit no está instalado (paquete exploitdb)")
            return 1
        except subprocess.CalledProcessError as exc:
            ui.error(f"searchsploit falló: {(exc.stderr or '').strip()[:200]}")
            return 1
        _render(term, findings)
    return 0

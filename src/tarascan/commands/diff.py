"""Compara los dos últimos escaneos de un objetivo: puertos, versiones y tecnologías."""

import argparse

from tarascan import store, ui


def _ports_map(snap: dict) -> dict[str, dict]:
    return {p["port"]: p for p in snap.get("ports", []) if p.get("port")}


def cmd_diff(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tarascan diff", description="compara los dos últimos escaneos de un objetivo")
    p.add_argument("target", nargs="?", help="objetivo (por defecto el activo / $T)")
    args = p.parse_args(argv)

    target = args.target or store.get_active_target()
    if not target:
        ui.error("no hay objetivo: pásalo como argumento o escanea uno primero")
        return 1

    history = store.load_target(target).get("history", [])
    if len(history) < 2:
        ui.error(f"necesito al menos dos escaneos de '{target}' para comparar "
                 f"(hay {len(history)}). Vuelve a lanzarle el recon: tarascan {target} --fresh")
        return 1

    old, new = history[-2], history[-1]
    ui.rule(f"diff · [{ui.PURPLE}]{ui.escape(target)}[/]")
    ui.console.print(f"[{ui.GREY}]comparando {old.get('ts', '?')}  ->  {new.get('ts', '?')}[/]\n")

    om, nm = _ports_map(old), _ports_map(new)
    nuevos = sorted(set(nm) - set(om), key=lambda x: int(x) if x.isdigit() else 0)
    cerrados = sorted(set(om) - set(nm), key=lambda x: int(x) if x.isdigit() else 0)
    comunes = sorted(set(om) & set(nm), key=lambda x: int(x) if x.isdigit() else 0)

    body = []
    for port in nuevos:
        svc = nm[port].get("service") or "?"
        body.append(ui.Text(f"+ {port}/tcp abierto NUEVO ({svc})", style="bold green"))
    for port in cerrados:
        svc = om[port].get("service") or "?"
        body.append(ui.Text(f"- {port}/tcp cerrado ({svc})", style="bold red"))
    for port in comunes:
        vo, vn = (om[port].get("version") or ""), (nm[port].get("version") or "")
        if vo != vn:
            body.append(ui.Text(f"! {port}/tcp cambió de versión: '{vo or '-'}' -> '{vn or '-'}'", style="bold yellow"))

    tech_new = sorted(set(new.get("tech", [])) - set(old.get("tech", [])))
    tech_gone = sorted(set(old.get("tech", [])) - set(new.get("tech", [])))
    for t in tech_new:
        body.append(ui.Text(f"+ tecnología nueva: {t}", style="green"))
    for t in tech_gone:
        body.append(ui.Text(f"- tecnología ya no vista: {t}", style="red"))

    if not body:
        body = [ui.Text("sin cambios entre los dos últimos escaneos", style=ui.GREY)]
    ui.panel("Cambios", "puertos, versiones y tecnologías que han cambiado", body, border=ui.ORANGE)
    return 0

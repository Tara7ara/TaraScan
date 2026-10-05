"""Workspaces de auditoría (ws) y bitácora con timestamp (note)."""

import argparse
import datetime
from pathlib import Path

from tarascan import store, ui

_SUBDIRS = ("scans", "evidence", "report")


def _ws_root() -> Path:
    return Path.home() / "audit"


def _init(name: str) -> int:
    base = _ws_root() / name
    try:
        for sub in _SUBDIRS:
            (base / sub).mkdir(parents=True, exist_ok=True)
        notes = base / "notes.md"
        if not notes.exists():
            notes.write_text(
                f"# Bitácora · {name}\n\nCreado {datetime.datetime.now():%Y-%m-%d %H:%M}\n\n",
                encoding="utf-8",
            )
    except OSError as exc:
        ui.error(f"no se pudo crear el workspace: {exc}")
        return 1
    store.set_active_workspace(str(base))
    ui.rule(f"workspace · [{ui.PURPLE}]{name}[/]")
    ui.panel("Workspace creado y activado", f"árbol estándar en {base}", [
        ui.Text(str(base)),
        ui.Text("├── scans/      salidas de nmap, gobuster, nuclei...", style=ui.GREY),
        ui.Text("├── evidence/   capturas y respuestas HTTP", style=ui.GREY),
        ui.Text("├── notes.md    cuaderno de bitácora", style=ui.GREY),
        ui.Text("└── report/     informe final", style=ui.GREY),
        ui.note("apunta cosas con: tarascan note \"lo que sea\""),
    ], border=ui.ORANGE)
    return 0


def _list() -> int:
    root = _ws_root()
    active = store.get_active_workspace()
    ui.rule("workspaces")
    if not root.is_dir() or not any(root.iterdir()):
        ui.panel("Workspaces", "en ~/audit/", [ui.Text("ninguno todavía: crea uno con 'tarascan ws init <nombre>'", style=ui.GREY)])
        return 0
    body = []
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        mark = " (activo)" if active and Path(active) == d else ""
        style = ui.ORANGE if mark else None
        body.append(ui.Text(f"{d.name}{mark}", style=style) if style else ui.Text(f"{d.name}{mark}"))
    ui.panel("Workspaces", "en ~/audit/", body, border=ui.ORANGE)
    return 0


def _use(name: str) -> int:
    base = _ws_root() / name
    if not base.is_dir():
        ui.error(f"no existe el workspace '{name}' (créalo con 'tarascan ws init {name}')")
        return 1
    store.set_active_workspace(str(base))
    ui.console.print(f"[{ui.ORANGE}]workspace activo:[/] {base}")
    return 0


def cmd_ws(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tarascan ws", description="gestión de workspaces de auditoría")
    sub = p.add_subparsers(dest="action", required=True)
    pi = sub.add_parser("init", help="crea y activa un workspace")
    pi.add_argument("name")
    sub.add_parser("list", help="lista los workspaces")
    pu = sub.add_parser("use", help="cambia el workspace activo")
    pu.add_argument("name")
    args = p.parse_args(argv)

    if args.action == "init":
        return _init(args.name)
    if args.action == "use":
        return _use(args.name)
    return _list()


def cmd_note(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tarascan note", description="apunta una línea con timestamp en el workspace activo")
    p.add_argument("message", nargs="+", help="el texto a apuntar")
    args = p.parse_args(argv)

    ws = store.get_active_workspace()
    if not ws:
        ui.error("no hay workspace activo: crea uno con 'tarascan ws init <nombre>'")
        return 1
    notes = Path(ws) / "notes.md"
    line = f"- `{datetime.datetime.now():%Y-%m-%d %H:%M:%S}` {' '.join(args.message)}\n"
    try:
        with notes.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError as exc:
        ui.error(f"no se pudo escribir la nota: {exc}")
        return 1
    ui.console.print(f"[{ui.ORANGE}]anotado[/] en {notes}")
    return 0

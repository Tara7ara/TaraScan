"""Escalada de privilegios offline: one-liners de GTFOBins (sudo/SUID/capabilities) desde un JSON local."""

import argparse
import json
import sys
from pathlib import Path

from tarascan import ui

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "gtfobins.json"
# Orden y etiqueta de cada técnica.
_TECHNIQUES = [
    ("sudo", "Por sudo (si aparece en 'sudo -l')"),
    ("suid", "Con bit SUID (binario local ./bin)"),
    ("capabilities", "Con capability cap_setuid+ep"),
]


def _load_db() -> dict:
    try:
        return json.loads(_DB_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _binname(token: str) -> str:
    """Normaliza '/usr/bin/find' o 'find' a 'find'."""
    return Path(token.strip()).name.lower()


def _show(name: str, entry: dict) -> None:
    body = []
    for key, label in _TECHNIQUES:
        lines = entry.get(key)
        if not lines:
            continue
        body.append(ui.Text(label, style=ui.PURPLE))
        for ln in lines:
            style = ui.ORANGE if not ln.startswith(" ") else ui.GREY
            body.append(ui.Text(f"  {ln}", style=style))
    if not body:
        body = [ui.Text("sin técnicas de privesc registradas para este binario", style=ui.GREY)]
    ui.panel(f"gtfobins · {name}", "one-liners para escalar a root", body, border=ui.ORANGE)


def cmd_gtfobins(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="tarascan gtfobins",
        description="escalada de privilegios offline (GTFOBins): sudo, SUID, capabilities",
    )
    p.add_argument("binario", nargs="*", help="binario(s) a consultar (o por stdin); sin args lista los disponibles")
    args = p.parse_args(argv)

    db = _load_db()
    if not db:
        ui.error("no se pudo cargar la base de datos de GTFOBins")
        return 1
    disponibles = sorted(k for k in db if not k.startswith("_"))

    # Entradas: argumentos, o por tubería (p.ej. 'sudo -l | grep ...').
    tokens = list(args.binario)
    if not tokens and not sys.stdin.isatty():
        tokens = [w for ln in sys.stdin.read().split() for w in [ln] if w]

    if not tokens:
        ui.rule("gtfobins · binarios disponibles")
        ui.panel("Disponibles", f"{len(disponibles)} binarios en la base local", [
            ui.Text(", ".join(disponibles)),
            ui.note("uso: tarascan gtfobins find vim awk   ·   o: sudo -l | tarascan gtfobins"),
            ui.dim("busca candidatos en la víctima con: find / -perm -4000 -type f 2>/dev/null   (SUID)"),
            ui.dim("                                   getcap -r / 2>/dev/null   (capabilities)"),
        ], border=ui.ORANGE)
        return 0

    ui.rule(f"gtfobins · [{ui.PURPLE}]{ui.escape(' '.join(_binname(t) for t in dict.fromkeys(tokens)))}[/]")
    vistos, encontrados = set(), 0
    for tok in tokens:
        name = _binname(tok)
        if not name or name in vistos:
            continue
        vistos.add(name)
        # Exacto, o el nombre antes del primer punto (vim.basic->vim, python3.11->python3).
        entry = db.get(name) or (db.get(name.split(".")[0]) if "." in name else None)
        if entry:
            _show(name, entry)
            encontrados += 1
    if not encontrados:
        ui.panel("gtfobins", "sin coincidencias", [
            ui.Text("ninguno de esos binarios está en la base local.", style=ui.GREY),
            ui.note("míralo en https://gtfobins.github.io/ ; o pásame el nombre exacto del binario."),
        ])
    return 0

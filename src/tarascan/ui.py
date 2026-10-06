"""Primitivas de UI compartidas por los subcomandos (paleta naranja/morado, sin azul)."""

from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console(emoji=False)

ORANGE = "#ff9e64"
PURPLE = "#9d7cd8"
GREY = "#787c99"


def dim(text: str) -> Text:
    """Línea de explicación (gris, cursiva)."""
    return Text(text, style=f"italic {GREY}")


def note(text: str) -> Text:
    """Nota de interpretación de un hallazgo (naranja, con flecha)."""
    return Text(f"→ {text}", style=ORANGE)


def warn(text: str) -> Text:
    """Hallazgo que conviene mirar (rojo)."""
    return Text(f"→ {text}", style="bold red")


def status(code) -> Text:
    """Pinta un código HTTP según su familia: verde <300, amarillo <400, rojo >=400."""
    try:
        c = int(code)
    except (ValueError, TypeError):
        return Text(str(code), style=GREY)
    color = "green" if c < 300 else "yellow" if c < 400 else "red"
    return Text(str(code), style=color)


def table(*columns: str) -> Table:
    t = Table(show_header=True, header_style=f"bold {ORANGE}")
    for c in columns:
        t.add_column(c, overflow="fold")
    return t


def panel(title: str, desc: str, body: list, border: str = GREY) -> None:
    """Pinta una sección en su caja: título, explicación y contenido."""
    parts: list = []
    if desc:
        parts.append(dim(desc))
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


def rule(text: str) -> None:
    console.print()
    console.rule(f"[bold {ORANGE}]tarascan[/] · {text}", style=GREY)
    console.print()


def error(msg: str) -> None:
    """Escribe un error a stderr, en rojo, sin interpretar markup."""
    Console(stderr=True, style="bold red").print(msg, markup=False, highlight=False)


__all__ = [
    "console", "ORANGE", "PURPLE", "GREY", "escape",
    "dim", "note", "warn", "status", "table", "panel", "rule", "error",
]

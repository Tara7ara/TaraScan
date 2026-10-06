"""Informe consolidado del objetivo (Markdown/HTML) desde la persistencia."""

import argparse
import datetime
import html as _html
import re
from pathlib import Path

from tarascan import store, ui

# Checklist de metodología (PTES/OWASP resumido): se marca lo que consta hecho.
_METHODOLOGY = [
    ("recon", "Reconocimiento (puertos, servicios, versiones)"),
    ("web", "Enumeración web (directorios, tecnologías, APIs)"),
    ("vulns", "Identificación de vulnerabilidades"),
    ("smb", "Enumeración SMB/NetBIOS"),
    ("exploit", "Explotación"),
    ("postexploit", "Post-explotación / escalada"),
]


def _build_markdown(data: dict) -> str:
    target = data["target"]
    now = datetime.datetime.now()
    lines = [
        f"# Informe tarascan · {target}",
        "",
        f"_Generado {now:%Y-%m-%d %H:%M}_",
        "",
        "## Resumen ejecutivo",
        "",
    ]
    def _port_num(p: dict) -> int:
        try:
            return int(p.get("port", 0))
        except (ValueError, TypeError):
            return 0

    ports = data.get("ports", [])
    open_ports = ", ".join(str(p.get("port")) for p in sorted(ports, key=_port_num) if p.get("port")) or "ninguno registrado"
    # Separa lo crítico (marcado con [!] en el recon) del resto.
    all_findings = data.get("findings", [])
    criticos = [f[3:].strip() for f in all_findings if f.startswith("[!]")]
    otros = [f for f in all_findings if not f.startswith("[!]")]
    lines += [
        f"- Objetivo: **{target}**",
        f"- Puertos abiertos: {open_ports}",
        f"- Servicios identificados: {len(ports)}",
        f"- Hallazgos críticos: {len(criticos)}" + (" (ver abajo)" if criticos else ""),
        "",
        "## Detalle técnico",
        "",
    ]
    if ports:
        lines += ["### Servicios", "", "| Puerto | Servicio | Versión |", "| --- | --- | --- |"]
        for p in sorted(ports, key=_port_num):
            lines.append(f"| {p.get('port', '-')} | {p.get('service', '-')} | {p.get('version') or '-'} |")
        lines.append("")
    if data.get("tech"):
        lines += ["### Tecnologías web", "", *[f"- {t}" for t in data["tech"]], ""]
    if criticos:
        lines += ["### Hallazgos críticos", "", *[f"- **{f}**" for f in criticos], ""]
    if otros:
        lines += ["### Otros hallazgos", "", *[f"- {f}" for f in otros], ""]
    scans = data.get("scans", {})
    if scans:
        lines += ["### Herramientas ejecutadas", ""]
        for name, info in sorted(scans.items()):
            lines.append(f"- **{name}** ({info.get('ts', '?')}): {info.get('resumen', '')}")
        lines.append("")

    lines += ["## Metodología", ""]
    done = set(data.get("phases", []))
    if ports:
        done.add("recon")
    if data.get("tech"):
        done.add("web")
    # Marca fases a partir de las herramientas que corrieron y los hallazgos.
    blob = " ".join(data.get("findings", [])).lower() + " " + " ".join(data.get("scans", {})).lower()
    if any(k in blob for k in ("nuclei", "nikto", "searchsploit", "exploit", "sqli", "cve", "vulner")):
        done.add("vulns")
    if any(k in blob for k in ("smb", "netexec", "enum4linux", "samba", "netbios", "nbtscan")):
        done.add("smb")
    for key, label in _METHODOLOGY:
        mark = "x" if key in done else " "
        lines.append(f"- [{mark}] {label}")
    lines.append("")

    ai = data.get("ai")
    if isinstance(ai, dict) and ai.get("text"):
        lines += [f"## Análisis del copiloto (IA · {ai.get('model', '?')})", "", ai["text"], ""]
    return "\n".join(lines)


def _to_html(md: str, target: str) -> str:
    """Render mínimo de Markdown a HTML (sin dependencias), con la paleta de tarascan."""
    def _inline(text: str) -> str:
        s = _html.escape(text)
        s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
        return s

    body = []
    in_table = False
    in_list = False
    for raw in md.splitlines():
        line = raw.rstrip()
        if line.startswith("| "):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if set("".join(cells)) <= {"-", " "}:
                continue
            if not in_table:
                body.append("<table>")
                in_table = True
            tag = "td"
            body.append("<tr>" + "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells) + "</tr>")
            continue
        if in_table:
            body.append("</table>")
            in_table = False
        if line.startswith("### "):
            body.append(f"<h3>{_html.escape(line[4:])}</h3>")
        elif line.startswith("## "):
            body.append(f"<h2>{_html.escape(line[3:])}</h2>")
        elif line.startswith("# "):
            body.append(f"<h1>{_html.escape(line[2:])}</h1>")
        elif line.startswith(("- [x] ", "- [ ] ")):
            if not in_list:
                body.append("<ul>")
                in_list = True
            mark = "☑" if line[3] == "x" else "☐"
            body.append(f"<li>{mark} {_inline(line[6:])}</li>")
        elif line.startswith("- "):
            if not in_list:
                body.append("<ul>")
                in_list = True
            body.append(f"<li>{_inline(line[2:])}</li>")
        else:
            if in_list:
                body.append("</ul>")
                in_list = False
            if line.startswith("_") and line.endswith("_"):
                body.append(f"<p class='meta'>{_html.escape(line.strip('_'))}</p>")
            elif line:
                body.append(f"<p>{_inline(line)}</p>")
    if in_table:
        body.append("</table>")
    if in_list:
        body.append("</ul>")
    style = (
        "body{background:#1a1b26;color:#c0caf5;font-family:system-ui,sans-serif;"
        "max-width:900px;margin:2rem auto;padding:0 1rem;line-height:1.5}"
        "h1,h2,h3{color:#ff9e64}h2{border-bottom:1px solid #787c99;padding-bottom:.2rem}"
        ".meta{color:#787c99}table{border-collapse:collapse;width:100%;margin:1rem 0}"
        "td{border:1px solid #787c99;padding:.3rem .6rem}tr:first-child td{color:#9d7cd8;font-weight:bold}"
        "li{margin:.2rem 0}code{background:#24283b;padding:.1rem .3rem;border-radius:3px;color:#ff9e64}"
        "strong{color:#ff9e64}"
    )
    return (
        f"<!doctype html><html lang='es'><head><meta charset='utf-8'>"
        f"<title>tarascan · {_html.escape(target)}</title><style>{style}</style></head>"
        f"<body>{''.join(body)}</body></html>"
    )


def cmd_report(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tarascan report", description="informe consolidado de la sesión de un objetivo")
    p.add_argument("target", nargs="?", help="objetivo (por defecto el activo / $T)")
    p.add_argument("-o", "--output", help="ruta de salida (por defecto report/ del workspace o el cwd)")
    p.add_argument("--html", action="store_true", help="genera HTML en vez de Markdown")
    args = p.parse_args(argv)

    target = args.target or store.get_active_target()
    if not target:
        ui.error("no hay objetivo: pásalo como argumento o escanea uno primero (se guarda solo)")
        return 1

    data = store.load_target(target)
    if not data.get("ports") and not data.get("findings"):
        ui.error(f"no hay datos guardados de '{target}'. Lánzale un recon primero: tarascan {target}")
        return 1

    md = _build_markdown(data)
    content = _to_html(md, target) if args.html else md
    ext = "html" if args.html else "md"
    fname = f"informe-{store.slug(target)}-{datetime.datetime.now():%Y%m%d-%H%M%S}.{ext}"

    if args.output:
        out = Path(args.output)
        if out.is_dir() or args.output.endswith("/"):
            out = out / fname
    else:
        ws = store.get_active_workspace()
        out = (Path(ws) / "report" / fname) if ws else Path.cwd() / fname

    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
    except OSError as exc:
        ui.error(f"no se pudo guardar el informe: {exc}")
        return 1

    ui.rule(f"informe · [{ui.PURPLE}]{ui.escape(target)}[/]")
    ui.panel("Informe generado", f"consolidado de {len(data.get('ports', []))} servicio(s) y {len(data.get('findings', []))} hallazgo(s)", [
        ui.Text(str(out), style=ui.ORANGE),
    ])
    return 0

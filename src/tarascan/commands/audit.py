"""Auditoría de config débil de ssh, tls o smb (algoritmos, protocolos, null session)."""

import argparse
import re
import subprocess

from tarascan import ui
from tarascan.scanners import netexec, sslscan

# Algoritmos SSH que conviene marcar si aparecen habilitados.
_WEAK_SSH = {
    "diffie-hellman-group1-sha1": "KEX obsoleto (grupo 1, SHA1)",
    "diffie-hellman-group14-sha1": "KEX con SHA1",
    "ssh-rsa": "firma ssh-rsa (SHA1), deprecada",
    "ssh-dss": "DSA, roto",
    "hmac-md5": "MAC MD5",
    "hmac-sha1": "MAC SHA1",
    "arcfour": "cifrado RC4",
    "3des-cbc": "3DES en modo CBC",
    "aes128-cbc": "AES-CBC (vulnerable a ataques de relleno)",
    "aes256-cbc": "AES-CBC (vulnerable a ataques de relleno)",
}


def _audit_ssh(target: str, port: str) -> None:
    try:
        out = subprocess.run(
            ["nmap", "-Pn", "-p", port, "--script", "ssh2-enum-algos,ssh-auth-methods",
             "-sV", target],
            capture_output=True, text=True, timeout=120, check=False,
        ).stdout
    except FileNotFoundError:
        ui.error("nmap no está instalado")
        return
    except subprocess.TimeoutExpired:
        ui.error("nmap agotó el tiempo de espera")
        return

    low = out.lower()
    hits = []
    for algo, why in _WEAK_SSH.items():
        if algo in low:
            hits.append(ui.warn(f"{algo}: {why}"))
    if "password" in low and "auth" in low:
        hits.append(ui.note("acepta autenticación por contraseña: candidato a fuerza bruta (tarascan <IP> --brute ssh)."))
    ver = re.search(r"ssh.*?openssh[_ ]?([\w.]+)", low)
    if ver:
        hits.append(ui.dim(f"versión detectada: OpenSSH {ver.group(1)} (comprueba CVE con: searchsploit openssh {ver.group(1)})"))
    if not hits:
        hits = [ui.dim("no se detectaron algoritmos débiles habituales (o el script no devolvió datos).")]
    ui.panel(f"audit ssh · {target}:{port}", "algoritmos débiles y métodos de login de SSH", hits, border=ui.ORANGE)


def _audit_tls(target: str, port: str) -> None:
    try:
        res = sslscan.scan(target, port)
    except FileNotFoundError:
        ui.error("sslscan no está instalado")
        return
    except subprocess.CalledProcessError as exc:
        ui.error(f"sslscan falló: {(exc.stderr or '').strip()[:200]}")
        return

    body = []
    if res["protocols"]:
        body.append(ui.dim("protocolos habilitados: " + ", ".join(res["protocols"])))
    for proto in res["insecure_protocols"]:
        body.append(ui.warn(f"{proto} habilitado: protocolo obsoleto, deshabilítalo."))
    for cipher in res["weak_ciphers"][:20]:
        body.append(ui.warn(f"cifrado débil: {cipher}"))
    cert = res.get("cert") or {}
    if cert.get("estado") == "CADUCADO":
        body.append(ui.warn("certificado CADUCADO."))
    if cert.get("firma") and "sha1" in cert["firma"].lower():
        body.append(ui.warn(f"certificado firmado con {cert['firma']} (SHA1)."))
    if not any(isinstance(x, ui.Text) and x.style and "red" in str(x.style) for x in body):
        body.append(ui.dim("sin protocolos/cifrados obsoletos destacables."))
    ui.panel(f"audit tls · {target}:{port}", "protocolos y cifrados TLS deprecados", body, border=ui.ORANGE)


def _audit_smb(target: str, port: str) -> None:
    try:
        res = netexec.scan(target)
    except FileNotFoundError:
        ui.error("netexec (nxc) no está instalado")
        return
    except subprocess.CalledProcessError as exc:
        ui.error(f"netexec falló: {(exc.stderr or '').strip()[:200]}")
        return

    body = []
    for line in res.get("host", []):
        body.append(ui.Text(f"  {line}"))
    joined = " ".join(res.get("host", []))
    if re.search(r"signing:\s*false", joined, re.I):
        body.append(ui.warn("SMB signing DESACTIVADO: vulnerable a relay (ntlmrelayx)."))
    if "Null Auth:True" in joined or re.search(r"null.*true", joined, re.I):
        body.append(ui.warn("sesión nula permitida: enumeración sin credenciales."))
    if re.search(r"smbv1:\s*true", joined, re.I):
        body.append(ui.warn("SMBv1 habilitado: protocolo obsoleto (EternalBlue)."))
    shares = res.get("shares", [])
    if shares:
        body.append(ui.note(f"{len(shares)} recurso(s) accesibles con sesión nula:"))
        body.extend(ui.Text(f"  {s}") for s in shares)
    if not body:
        body = [ui.dim("sin datos por sesión nula (SMB puede estar bien configurado).")]
    ui.panel(f"audit smb · {target}", "null sessions, SMB signing y recursos anónimos", body, border=ui.ORANGE)


_AUDITORS = {"ssh": _audit_ssh, "tls": _audit_tls, "smb": _audit_smb}
_DEFAULT_PORT = {"ssh": "22", "tls": "443", "smb": "445"}
# Puertos que, si están abiertos, delatan cada servicio (para el modo automático).
_SERVICE_PORTS = {"ssh": {"22"}, "tls": {"443", "8443"}, "smb": {"139", "445"}}


def _services_from_cache(target: str) -> list[str]:
    """Servicios auditables cuyos puertos salían abiertos en el último escaneo."""
    try:
        from tarascan import store
        known = {p.get("port") for p in store.load_target(target).get("ports", [])}
    except Exception:  # noqa: BLE001
        return []
    return [svc for svc, ports in _SERVICE_PORTS.items() if known & ports]


def cmd_audit(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="tarascan audit",
        description="auditoría de config de ssh, tls o smb (sin servicio: audita los abiertos)",
        usage="tarascan audit [ssh|tls|smb] <objetivo> [-p PUERTO]",
    )
    p.add_argument("items", nargs="+", metavar="[servicio] objetivo",
                   help="servicio (ssh/tls/smb) y objetivo; sin servicio audita los que salían abiertos")
    p.add_argument("-p", "--port", help="puerto (por defecto el estándar del servicio)")
    args = p.parse_args(argv)

    # El primer positional es el servicio solo si es uno conocido; si no, objetivo.
    manual = args.items[0] in _AUDITORS
    if manual:
        if len(args.items) < 2:
            ui.error("falta el objetivo: tarascan audit ssh <IP>")
            return 1
        servicios, target = [args.items[0]], args.items[1]
    else:
        target = args.items[0]
        servicios = _services_from_cache(target)
        if not servicios:
            ui.error("sin servicios auditables en caché. Indica uno (tarascan audit ssh <IP>) "
                     "o escanea el objetivo antes (tarascan <IP>).")
            return 1
        ui.console.print(f"[{ui.GREY}]auditando los servicios abiertos: {', '.join(servicios)}[/]")

    ui.rule(f"audit · [{ui.PURPLE}]{ui.escape(target)}[/]")
    for svc in servicios:
        port = args.port or _DEFAULT_PORT[svc]
        if manual:  # aviso de puerto cerrado solo en modo manual
            try:
                from tarascan import store
                known = {p.get("port") for p in store.load_target(target).get("ports", [])}
                if known and port not in known and not args.port:
                    ui.console.print(f"[{ui.GREY}]aviso: el puerto {port} no salía abierto en el último "
                                     f"escaneo de {target}; audito igual por si acaso.[/]")
            except Exception:  # noqa: BLE001
                pass
        with ui.console.status(f"[{ui.ORANGE}]auditando {svc}[/][{ui.GREY}]…[/]", spinner="dots"):
            _AUDITORS[svc](target, port)
    return 0

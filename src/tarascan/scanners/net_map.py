"""Módulo de descubrimiento y mapeo de red local (barrido en paralelo de hosts activos, nombres, S.O., puertos, MACs y fabricantes)."""

import concurrent.futures
import ipaddress
import re
import socket
import subprocess
from pathlib import Path
from typing import Any

import dns.resolver
import dns.reversename

from tarascan.scanners import nbtscan

OUI_FILE = Path("/usr/share/nmap/nmap-mac-prefixes")
COMMON_PORTS = [21, 22, 23, 53, 80, 139, 443, 445, 3389, 8080]


def detect_local_network() -> dict[str, Any] | None:
    """Detecta la interfaz por defecto, gateway, IP local y subred CIDR."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return None

    parts = out.split()
    gw = parts[parts.index("via") + 1] if "via" in parts else None
    iface = parts[parts.index("dev") + 1] if "dev" in parts else None
    if not iface:
        return None

    try:
        addr_out = subprocess.check_output(
            ["ip", "-o", "-f", "inet", "addr", "show", iface],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return None

    lines = addr_out.splitlines()
    if not lines:
        return None

    ip_cidr = lines[0].split()[3]
    try:
        ip_obj = ipaddress.ip_interface(ip_cidr)
    except ValueError:
        return None

    own_mac = None
    mac_path = Path(f"/sys/class/net/{iface}/address")
    if mac_path.is_file():
        try:
            own_mac = mac_path.read_text(encoding="utf-8").strip().lower()
        except OSError:
            pass

    return {
        "interface": iface,
        "gateway": gw,
        "local_ip": str(ip_obj.ip),
        "cidr": str(ip_obj.network),
        "own_mac": own_mac,
    }


def load_oui_prefixes(path: Path = OUI_FILE) -> dict[str, str]:
    """Carga los prefijos OUI (6 caracteres hexadecimales) y su fabricante."""
    table: dict[str, str] = {}
    if not path.is_file():
        return table
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                prefix, vendor = parts
                table[prefix.upper()] = vendor.strip()
    except OSError:
        pass
    return table


def get_arp_table() -> dict[str, str]:
    """Lee /proc/net/arp y devuelve un mapa {IP: MAC_en_minúsculas}."""
    table: dict[str, str] = {}
    arp_file = Path("/proc/net/arp")
    if not arp_file.is_file():
        return table
    try:
        content = arp_file.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ip, mac = parts[0], parts[3].lower()
                if mac not in ("00:00:00:00:00:00", "<incomplete>"):
                    table[ip] = mac
    except OSError:
        pass
    return table


def parse_nmap_sn(stdout: str) -> dict[str, str]:
    """Parsea la salida grepable de nmap -sn y devuelve mapa {ip: hostname}."""
    hosts: dict[str, str] = {}
    for line in stdout.splitlines():
        if not line.startswith("Host:") or "Status: Up" not in line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[1]
            hostname = ""
            m = re.search(r"\((.*?)\)", line)
            if m:
                hostname = m.group(1).strip()
            hosts[ip] = hostname
    return hosts


def split_network(cidr: str, max_chunks: int = 8) -> list[str]:
    """Divide subredes grandes (> /24) en bloques /24 para paralelizar el barrido."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return [cidr]

    if net.prefixlen >= 24:
        return [str(net)]

    subnets = list(net.subnets(new_prefix=24))
    if len(subnets) <= 16:
        return [str(s) for s in subnets]
    step = min(3, 24 - net.prefixlen)
    return [str(s) for s in net.subnets(new_prefix=net.prefixlen + step)]


def _scan_nmap_chunk(chunk_cidr: str) -> dict[str, str]:
    """Barrido rápido de un bloque con nmap -sn."""
    cmd = [
        "nmap",
        "-sn",
        "-T4",
        "--min-parallelism", "50",
        "--max-rtt-timeout", "350ms",
        "-oG", "-",
        chunk_cidr,
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return parse_nmap_sn(res.stdout)
    except Exception:
        return {}


def _scan_nbt_chunk(chunk_cidr: str) -> dict[str, str]:
    """Descubre nombres NetBIOS en paralelo si nbtscan está disponible."""
    try:
        results = nbtscan.scan(chunk_cidr)
        return {h["ip"]: h["name"] for h in results if h.get("ip") and h.get("name")}
    except Exception:
        return {}


def _resolve_dns_fast(ip: str) -> tuple[str, str]:
    """Resuelve el nombre inverso mediante dnspython con timeout muy estricto (0.3s)."""
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 0.3
        resolver.lifetime = 0.3
        answers = resolver.resolve(rev_name, "PTR")
        if answers:
            return ip, str(answers[0]).rstrip(".")
    except Exception:
        pass
    return ip, ""


def format_windows_version(ver_str: str) -> str:
    """Traduce un número de compilación/versión de Windows a nombre reconocible."""
    parts = ver_str.split(".")
    if len(parts) >= 3 and parts[0] == "10" and parts[1] == "0":
        try:
            build = int(parts[2])
            if build >= 22000:
                return f"Windows 11 (b{build})"
            return f"Windows 10 (b{build})"
        except ValueError:
            return f"Windows {ver_str}"
    if ver_str.startswith("6.3"):
        return "Windows 8.1"
    if ver_str.startswith("6.1"):
        return "Windows 7"
    return f"Windows {ver_str}" if ver_str else ""


def parse_rdp_ntlm(stdout: str) -> dict[str, dict[str, str]]:
    """Parsea la salida de rdp-ntlm-info y devuelve {ip: {'name': ..., 'os': ...}}."""
    results: dict[str, dict[str, str]] = {}
    current_ip = None
    for line in stdout.splitlines():
        if line.startswith("Nmap scan report for "):
            current_ip = line.split()[-1].strip("()")
            results[current_ip] = {}
        elif current_ip and "NetBIOS_Computer_Name:" in line:
            results[current_ip]["name"] = line.split(":", 1)[1].strip()
        elif current_ip and "DNS_Computer_Name:" in line and "name" not in results[current_ip]:
            results[current_ip]["name"] = line.split(":", 1)[1].strip()
        elif current_ip and "Product_Version:" in line:
            ver = line.split(":", 1)[1].strip()
            results[current_ip]["os"] = format_windows_version(ver)
    return results


def parse_nxc_smb(stdout: str) -> dict[str, dict[str, str]]:
    """Parsea la salida de nxc smb y devuelve {ip: {'name': ..., 'os': ...}}."""
    ansi_re = re.compile(r"\x1b\[[0-9;]*m")
    results: dict[str, dict[str, str]] = {}
    for line in stdout.splitlines():
        line = ansi_re.sub("", line).replace("\x00", "").strip()
        if not line.startswith("SMB"):
            continue
        parts = line.split(None, 4)
        if len(parts) >= 5:
            ip = parts[1]
            name = parts[3]
            msg = parts[4]
            os_match = re.search(r"\[\*\]\s*(.*?)\s*\(name:", msg)
            if not os_match:
                os_match = re.search(r"\[\*\]\s*(.*?)\s*\(", msg)
            os_str = os_match.group(1).strip() if os_match else ""
            results[ip] = {
                "name": name if name and name != ip else "",
                "os": os_str,
            }
    return results


def parse_ssh_os(banner: str) -> str:
    """Extrae el sistema operativo a partir del banner SSH."""
    if not banner:
        return ""
    low = banner.lower()
    if "ubuntu" in low:
        return "Linux (Ubuntu)"
    if "debian" in low:
        return "Linux (Debian)"
    if "arch" in low:
        return "Linux (Arch)"
    if "raspbian" in low or "raspberry" in low:
        return "Linux (Raspberry Pi)"
    if "freebsd" in low:
        return "FreeBSD"
    if "cisco" in low:
        return "Cisco IOS"
    if "openssh" in low:
        return "Linux (OpenSSH)"
    return banner.split()[0] if banner else ""


def _probe_host_ports(ip: str) -> tuple[str, list[int], dict[int, str]]:
    """Comprueba puertos comunes y captura banners básicos sin bloquear."""
    opened: list[int] = []
    banners: dict[int, str] = {}
    for p in COMMON_PORTS:
        s = socket.socket()
        s.settimeout(0.12)
        try:
            s.connect((ip, p))
            opened.append(p)
            if p in (21, 22):
                s.settimeout(0.15)
                b = s.recv(128).decode(errors="ignore").strip()
                if b:
                    banners[p] = b
            elif p in (80, 8080):
                s.settimeout(0.15)
                req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: tarascan\r\n\r\n"
                s.sendall(req.encode())
                res = s.recv(512).decode(errors="ignore")
                m = re.search(r"Server:\s*(.+)", res, re.IGNORECASE)
                if m:
                    banners[p] = m.group(1).strip().splitlines()[0]
        except Exception:
            pass
        finally:
            s.close()
    return ip, opened, banners


def _get_local_os() -> str:
    """Detecta el SO de la máquina local desde /etc/os-release."""
    os_release = Path("/etc/os-release")
    if os_release.is_file():
        try:
            for line in os_release.read_text(encoding="utf-8").splitlines():
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip('"\'')
        except OSError:
            pass
    return "Linux"


def scan(
    cidr: str, local_info: dict[str, Any] | None = None, max_workers: int = 8
) -> list[dict[str, str]]:
    """Lanza barridos en paralelo (hosts, puertos, RDP/SMB, DNS) y enriquece S.O., nombres y puertos."""
    target_net = None
    try:
        target_net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        pass

    chunks = split_network(cidr, max_chunks=max_workers)
    nmap_hosts: dict[str, str] = {}
    nbt_hosts: dict[str, str] = {}

    # Paso 1: Descubrimiento de hosts en paralelo (nmap -sn y nbtscan por bloques)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        nmap_futs = [executor.submit(_scan_nmap_chunk, chunk) for chunk in chunks]
        nbt_futs = [executor.submit(_scan_nbt_chunk, chunk) for chunk in chunks]

        for fut in concurrent.futures.as_completed(nmap_futs):
            try:
                nmap_hosts.update(fut.result())
            except Exception:
                pass

        for fut in concurrent.futures.as_completed(nbt_futs):
            try:
                nbt_hosts.update(fut.result())
            except Exception:
                pass

    arp_table = get_arp_table()
    oui_table = load_oui_prefixes()

    gw_ip = local_info.get("gateway") if local_info else None
    local_ip = local_info.get("local_ip") if local_info else None
    own_mac = local_info.get("own_mac") if local_info else None

    # Conjunto unificado de IPs vivas
    all_ips = set(nmap_hosts.keys())
    all_ips.update(nbt_hosts.keys())
    for arp_ip in arp_table:
        if target_net:
            try:
                if ipaddress.ip_address(arp_ip) in target_net:
                    all_ips.add(arp_ip)
            except ValueError:
                pass
        else:
            all_ips.add(arp_ip)

    if local_ip:
        if not target_net or (ipaddress.ip_address(local_ip) in target_net):
            all_ips.add(local_ip)

    # Paso 2: Chequeo rápido de puertos comunes y banners en paralelo
    host_ports: dict[str, list[int]] = {}
    host_banners: dict[str, dict[int, str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, max(1, len(all_ips) * 2))) as ex:
        for ip, opened, banners in ex.map(_probe_host_ports, all_ips):
            host_ports[ip] = opened
            host_banners[ip] = banners

    # Agrupar hosts según servicios detectados para escaneo dirigido
    rdp_ips = [ip for ip in all_ips if 3389 in host_ports.get(ip, [])]
    smb_ips = [ip for ip in all_ips if 445 in host_ports.get(ip, []) or 139 in host_ports.get(ip, [])]

    # Paso 3: Extracción concurrente de nombres y S.O. profundo (RDP NTLM, SMB nxc, DNS)
    rdp_info: dict[str, dict[str, str]] = {}
    smb_info: dict[str, dict[str, str]] = {}
    dns_hosts: dict[str, str] = {}

    def _run_rdp_batch(ips: list[str]) -> dict[str, dict[str, str]]:
        if not ips:
            return {}
        try:
            cmd = ["nmap", "-p", "3389", "--script", "rdp-ntlm-info", "-Pn"] + ips
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return parse_rdp_ntlm(res.stdout)
        except Exception:
            return {}

    def _run_smb_batch(ips: list[str]) -> dict[str, dict[str, str]]:
        if not ips:
            return {}
        try:
            cmd = ["nxc", "smb"] + ips
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return parse_nxc_smb(res.stdout)
        except Exception:
            return {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as deep_executor:
        f_rdp = deep_executor.submit(_run_rdp_batch, rdp_ips)
        f_smb = deep_executor.submit(_run_smb_batch, smb_ips)

        unresolved_ips = [
            ip for ip in all_ips
            if not nmap_hosts.get(ip) and not nbt_hosts.get(ip)
        ]
        f_dns = deep_executor.map(_resolve_dns_fast, unresolved_ips)

        try:
            rdp_info = f_rdp.result()
        except Exception:
            pass
        try:
            smb_info = f_smb.result()
        except Exception:
            pass
        try:
            for ip, name in f_dns:
                if name:
                    dns_hosts[ip] = name
        except Exception:
            pass

    # Paso 4: Sintetizar información por host
    local_os_name = _get_local_os()
    devices: list[dict[str, str]] = []

    for ip in all_ips:
        # 1. Nombre de host
        hostname = (
            rdp_info.get(ip, {}).get("name")
            or smb_info.get(ip, {}).get("name")
            or nbt_hosts.get(ip)
            or nmap_hosts.get(ip)
            or dns_hosts.get(ip)
            or ""
        )
        if not hostname and ip == local_ip:
            try:
                hostname = socket.gethostname()
            except Exception:
                pass
        if not hostname and ip == gw_ip:
            try:
                hostname = socket.gethostbyaddr(gw_ip)[0]
            except Exception:
                pass

        # 2. MAC y fabricante
        mac = arp_table.get(ip, "")
        if not mac and local_ip and ip == local_ip and own_mac:
            mac = own_mac

        vendor = ""
        if mac:
            clean_mac = mac.replace(":", "").replace("-", "").upper()
            prefix = clean_mac[:6]
            vendor = oui_table.get(prefix, "")

        # 3. Puertos abiertos
        ports_list = host_ports.get(ip, [])
        ports_str = ", ".join(str(p) for p in sorted(ports_list)) if ports_list else "-"

        # 4. Sistema Operativo / Versión
        os_name = (
            smb_info.get(ip, {}).get("os")
            or rdp_info.get(ip, {}).get("os")
            or ""
        )
        if not os_name:
            if ip == local_ip:
                os_name = local_os_name
            elif 22 in ports_list:
                os_name = parse_ssh_os(host_banners.get(ip, {}).get(22, ""))
                if not os_name:
                    os_name = "Linux (SSH)"
            elif 3389 in ports_list or 445 in ports_list:
                os_name = "Windows"
            elif 80 in ports_list or 8080 in ports_list:
                http_srv = host_banners.get(ip, {}).get(80) or host_banners.get(ip, {}).get(8080)
                if http_srv:
                    if "win" in http_srv.lower() or "iis" in http_srv.lower():
                        os_name = f"Windows ({http_srv})"
                    elif "unix" in http_srv.lower() or "linux" in http_srv.lower() or "ubuntu" in http_srv.lower():
                        os_name = f"Linux ({http_srv.split()[0]})"
                    else:
                        os_name = f"Web ({http_srv.split()[0]})"
            elif vendor:
                vlow = vendor.lower()
                if "cisco" in vlow or "huawei" in vlow or "juniper" in vlow or "mikrotik" in vlow:
                    os_name = "Router / Switch"
                elif "apple" in vlow:
                    os_name = "Apple macOS / iOS"
                elif "synology" in vlow or "qnap" in vlow:
                    os_name = "NAS"
                elif "raspberry" in vlow:
                    os_name = "Linux (Raspberry Pi)"

        # 5. Roles
        roles = []
        if gw_ip and ip == gw_ip:
            roles.append("gateway")
        if local_ip and ip == local_ip:
            roles.append("este equipo")

        devices.append(
            {
                "ip": ip,
                "hostname": hostname or "-",
                "os": os_name or "-",
                "ports": ports_str,
                "mac": mac or "-",
                "vendor": vendor or "-",
                "role": ", ".join(roles) if roles else "",
            }
        )

    def _ip_sort_key(item: dict[str, str]):
        try:
            return (0, ipaddress.ip_address(item["ip"]))
        except ValueError:
            return (1, item["ip"])

    devices.sort(key=_ip_sort_key)
    return devices

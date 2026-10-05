"""OSINT pasivo de un dominio: crt.sh, registros DNS, SPF/DMARC/DKIM y cabeceras."""

import argparse
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from tarascan import ui

_UA = "Mozilla/5.0 (tarascan osint)"
_SEC_HEADERS = {
    "strict-transport-security": "HSTS (fuerza HTTPS)",
    "content-security-policy": "CSP (mitiga XSS/inyección)",
    "x-frame-options": "X-Frame-Options (anti-clickjacking)",
    "x-content-type-options": "X-Content-Type-Options (anti MIME-sniffing)",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _crtsh(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, ValueError, TimeoutError):
        return []
    subs: set[str] = set()
    for row in data:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain):
                subs.add(name)
    return sorted(subs)


def _txt(name: str) -> list[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(name, "TXT", lifetime=10)
        out = []
        for r in answers:
            out.append(b"".join(getattr(r, "strings", [str(r).encode()])).decode("utf-8", "replace"))
        return out
    except Exception:  # noqa: BLE001 - sin registro / sin resolver: lista vacía
        return []


def _resolve(name: str, rtype: str) -> list[str]:
    try:
        import dns.resolver
        return [str(r).rstrip(".") for r in dns.resolver.resolve(name, rtype, lifetime=10)]
    except Exception:  # noqa: BLE001
        return []


def _dns_records(domain: str) -> list:
    body = []
    a = _resolve(domain, "A") + _resolve(domain, "AAAA")
    ns = _resolve(domain, "NS")
    mx = sorted(_resolve(domain, "MX"))
    if a:
        body.append(ui.Text("A/AAAA: " + ", ".join(a)))
    ns_hosts = [r.split()[-1] for r in ns]
    if ns_hosts:
        body.append(ui.dim("NS: " + ", ".join(ns_hosts)))
    # MX viene como "<prio> <host>"; un "<prio>" solo (host vacío) es null MX.
    mx_real = [r for r in mx if len(r.split()) >= 2 and r.split()[-1]]
    if mx_real:
        body.append(ui.dim("MX: " + "; ".join(mx_real)))
    elif mx:
        body.append(ui.dim("MX: null MX (RFC 7505): el dominio declara que no recibe correo."))
    # Pista de posible cloud/CDN delante (útil para saber a qué apuntas de verdad).
    joined = " ".join(a + ns_hosts).lower()
    for prov, hint in (("cloudflare", "Cloudflare"), ("amazonaws", "AWS"),
                       ("azure", "Azure"), ("googleusercontent", "Google Cloud")):
        if prov in joined:
            body.append(ui.note(f"parece detrás de {hint}: la IP puede ser del proveedor, no del origen real."))
            break
    if not body:
        body.append(ui.Text("sin registros DNS resolubles (o sin resolver)", style=ui.GREY))
    return body


def _mail_policies(domain: str) -> list:
    body = []
    spf = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]
    if spf:
        rec = spf[0]
        body.append(ui.Text(f"SPF: {rec}"))
        if "~all" in rec:
            body.append(ui.warn("SPF termina en ~all (softfail): un correo falsificado se acepta marcado, no se rechaza."))
        elif "?all" in rec or "+all" in rec:
            body.append(ui.warn("SPF permisivo (?all/+all): prácticamente permite suplantación."))
        elif "-all" in rec:
            body.append(ui.dim("SPF con -all (hardfail): correcto."))
    else:
        body.append(ui.warn("sin SPF: el dominio es suplantable por correo."))

    dmarc = [t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if dmarc:
        rec = dmarc[0]
        body.append(ui.Text(f"DMARC: {rec}"))
        if "p=none" in rec.replace(" ", ""):
            body.append(ui.warn("DMARC con p=none: solo monitoriza, no bloquea la suplantación."))
    else:
        body.append(ui.warn("sin DMARC: no hay política contra la suplantación."))

    found, revoked = [], []
    for sel in ("default", "google", "selector1", "selector2", "k1", "mail"):
        recs = _txt(f"{sel}._domainkey.{domain}")
        for r in recs:
            if "dkim1" not in r.lower():
                continue
            # p= con contenido = clave real; p= vacío = selector revocado/sin clave.
            m = re.search(r"p=\s*([A-Za-z0-9+/=]*)", r)
            (found if (m and m.group(1)) else revoked).append(sel)
            break
    if found:
        body.append(ui.dim(f"DKIM: selectores con clave: {', '.join(found)}"))
    if revoked:
        body.append(ui.dim(f"DKIM: selectores presentes pero sin clave (revocados): {', '.join(revoked)}"))
    if not found and not revoked:
        body.append(ui.dim("DKIM: sin selectores habituales (puede usar otros)."))
    return body


def _headers(domain: str) -> list:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        req = urllib.request.Request(url, headers={"User-Agent": _UA}, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
            body.append(ui.Text(f"{url} -> {resp.status}", style=ui.PURPLE))
            present = [desc for h, desc in _SEC_HEADERS.items() if h in hdrs]
            missing = [desc for h, desc in _SEC_HEADERS.items() if h not in hdrs]
            if present:
                body.append(ui.dim("presentes: " + "; ".join(present)))
            if missing:
                body.append(ui.warn("faltan: " + "; ".join(missing)))
            acao = hdrs.get("access-control-allow-origin")
            if acao == "*":
                body.append(ui.warn("CORS Access-Control-Allow-Origin: * (abierto a cualquier origen)."))
            if "server" in hdrs:
                body.append(ui.dim(f"Server: {hdrs['server']}"))
            return body
        except (urllib.error.URLError, TimeoutError, ValueError):
            continue
    body.append(ui.Text("no respondió por HTTP/HTTPS", style=ui.GREY))
    return body


def cmd_osint(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tarascan osint", description="OSINT pasivo de un dominio")
    p.add_argument("domain", help="dominio a investigar (p.ej. example.com)")
    args = p.parse_args(argv)

    domain = args.domain.strip().lower().lstrip(".")
    # osint es OSINT de dominio: una IP no tiene crt.sh ni SPF/DMARC/DKIM.
    try:
        import ipaddress
        ipaddress.ip_address(domain)
        ui.error("osint es para dominios, no IPs. Para una IP usa 'tarascan <IP>' "
                 "(recon) o 'tarascan web http://<IP>'.")
        return 1
    except ValueError:
        pass
    if "." not in domain:
        ui.error(f"'{domain}' no parece un dominio. Ejemplo: tarascan osint example.com")
        return 1
    ui.rule(f"OSINT pasivo · [{ui.PURPLE}]{ui.escape(domain)}[/]")

    with ui.console.status(f"[{ui.ORANGE}]consultando crt.sh[/][{ui.GREY}]… (Certificate Transparency)[/]", spinner="dots"):
        subs = _crtsh(domain)
    if subs:
        body = [ui.Text(s) for s in subs[:60]]
        if len(subs) > 60:
            body.append(ui.Text(f"... y {len(subs) - 60} más", style=ui.GREY))
        body.append(ui.note(f"{len(subs)} subdominio(s) históricos; no todos tienen por qué seguir vivos."))
    else:
        body = [ui.Text("sin resultados en crt.sh (o sin conexión)", style=ui.GREY)]
    ui.panel("Subdominios (crt.sh)", "subdominios en certificados públicos, sin tocar su DNS", body, border=ui.ORANGE)

    with ui.console.status(f"[{ui.ORANGE}]resolviendo DNS[/][{ui.GREY}]… (A/NS/MX)[/]", spinner="dots"):
        ui.panel("Registros DNS", "a dónde apunta el dominio (A/AAAA, NS, MX)", _dns_records(domain), border=ui.ORANGE)

    with ui.console.status(f"[{ui.ORANGE}]revisando políticas de correo[/][{ui.GREY}]… (SPF/DMARC/DKIM)[/]", spinner="dots"):
        ui.panel("Correo (SPF/DMARC/DKIM)", "si el dominio se puede suplantar por email", _mail_policies(domain), border=ui.ORANGE)

    with ui.console.status(f"[{ui.ORANGE}]comprobando cabeceras[/][{ui.GREY}]…[/]", spinner="dots"):
        ui.panel("Cabeceras de seguridad", "cabeceras HTTP defensivas presentes/ausentes y CORS", _headers(domain), border=ui.ORANGE)
    return 0

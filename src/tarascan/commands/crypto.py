"""Utilidades offline de cripto: hash (tipo + Hashcat/John), decode (cascada) y jwt."""

import argparse
import base64
import binascii
import codecs
import datetime
import html
import json
import re
import sys
import urllib.parse

from tarascan import ui


def _stdin_lines() -> list[str]:
    """Líneas no vacías de la tubería (vacío si stdin es una terminal)."""
    if sys.stdin is None or sys.stdin.isatty():
        return []
    return [ln.strip() for ln in sys.stdin.read().splitlines() if ln.strip()]


def _arg_or_stdin(value: str | None) -> str | None:
    """Devuelve el argumento si se pasó; si no, la primera línea de la tubería."""
    if value:
        return value
    lines = _stdin_lines()
    return lines[0] if lines else None


# --------------------------------------------------------------------------- #
# hash
# --------------------------------------------------------------------------- #
# Cada entrada: (etiqueta, modo hashcat -m, formato john). None = no aplica.
# El orden importa: lo más probable primero.
def _identify_hash(h: str) -> list[tuple[str, str, str]]:
    h = h.strip()
    out: list[tuple[str, str, str]] = []
    hexlike = bool(re.fullmatch(r"[0-9a-fA-F]+", h))
    n = len(h)

    # Hashes con prefijo inequívoco ($...$): los más fáciles y los más seguros.
    prefixes = [
        (r"^\$2[aby]\$\d{2}\$", "bcrypt", "3200", "bcrypt"),
        (r"^\$1\$", "md5crypt (Unix)", "500", "md5crypt"),
        (r"^\$5\$", "sha256crypt (Unix)", "7400", "sha256crypt"),
        (r"^\$6\$", "sha512crypt (Unix)", "1800", "sha512crypt"),
        (r"^\$y\$", "yescrypt (Unix)", "", "yescrypt"),
        (r"^\$apr1\$", "Apache MD5 (htpasswd)", "1600", "md5crypt-a"),
        (r"^\$argon2", "Argon2", "", "argon2"),
        (r"^\{SSHA\}", "SSHA (LDAP)", "111", "ssha"),
        (r"^\$P\$|\$H\$", "phpass (WordPress/phpBB)", "400", "phpass"),
        # Kerberos de Active Directory: oro puro en eJPT/CPTS.
        (r"^\$krb5tgs\$", "Kerberos 5 TGS-REP (Kerberoasting)", "13100", "krb5tgs"),
        (r"^\$krb5asrep\$", "Kerberos 5 AS-REP (ASREProast)", "18200", "krb5asrep"),
        (r"^\$krb5pa\$", "Kerberos 5 AS-REQ Pre-Auth", "7500", "krb5pa-md5"),
        (r"^pbkdf2_sha256\$", "Django (PBKDF2-SHA256)", "10000", "django"),
    ]
    for pat, label, hc, john in prefixes:
        if re.search(pat, h):
            out.append((label, hc, john))

    # pwdump/secretsdump: LM:NT (32 hex : 32 hex). Se crackea la parte NT.
    if re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", h):
        out.append(("LM:NTLM (pwdump); crackea la parte NT", "1000", "nt"))

    # net-NTLM / responder (usuario::dominio:...)
    if h.count(":") >= 4 and "::" in h:
        out.append(("NetNTLMv2 (Responder/relay)", "5600", "netntlmv2"))
        out.append(("NetNTLMv1", "5500", "netntlm"))

    # MySQL moderno: *40 hex en mayúscula
    if re.fullmatch(r"\*[0-9A-Fa-f]{40}", h):
        out.append(("MySQL 4.1+ (SHA1 doble)", "300", "mysql-sha1"))

    if hexlike:
        length_map = {
            16: [("MySQL < 4.1", "200", "mysql")],
            32: [("MD5", "0", "raw-md5"),
                 ("NTLM", "1000", "nt"),
                 ("MD4", "900", "raw-md4"),
                 ("LM", "3000", "lm")],
            40: [("SHA1", "100", "raw-sha1")],
            56: [("SHA224", "1300", "raw-sha224")],
            64: [("SHA256", "1400", "raw-sha256")],
            96: [("SHA384", "10800", "raw-sha384")],
            128: [("SHA512", "1700", "raw-sha512")],
        }
        out.extend(length_map.get(n, []))
        if n == 32 and not out:
            out.append(("hash hex de 32 (MD5/NTLM probable)", "0", "raw-md5"))

    if not out:
        out.append(("desconocido: no casa con ningún patrón habitual", "", ""))
    return out


def _hash_detallado(h: str) -> None:
    """Salida completa para UN hash: candidatos + ejemplos de crackeo."""
    ui.rule(f"identificar hash [{ui.PURPLE}]{ui.escape(h[:48] + ('…' if len(h) > 48 else ''))}[/]")
    cands = _identify_hash(h)

    t = ui.table("Tipo probable", "Hashcat", "John")
    for label, hc, john in cands:
        hc_txt = f"-m {hc}" if hc else "-"
        john_txt = f"--format={john}" if john else "-"
        t.add_row(label, ui.Text(hc_txt, style=ui.ORANGE), ui.Text(john_txt, style=ui.ORANGE))
    ui.panel("Tipos candidatos", f"longitud {len(h)}; ordenados por probabilidad", [t], border=ui.ORANGE)

    best = cands[0]
    if best[1]:
        ex = [
            ui.dim("ejemplos listos para pegar (ajusta la wordlist):"),
            ui.Text(f"hashcat -m {best[1]} hash.txt /usr/share/wordlists/rockyou.txt", style=ui.ORANGE),
            ui.Text(f"john --format={best[2]} --wordlist=/usr/share/wordlists/rockyou.txt hash.txt", style=ui.ORANGE),
        ]
        ui.panel("Crackear", f"para el candidato más probable ({best[0]})", ex)


def _hash_tabla(hashes: list[str]) -> None:
    """Salida compacta para varios hashes (p.ej. `cat hashes.txt | tarascan hash`)."""
    ui.rule(f"identificar hashes [{ui.PURPLE}]{len(hashes)} entradas[/]")
    t = ui.table("Entrada", "Tipo probable", "Hashcat", "John")
    for h in hashes:
        label, hc, john = _identify_hash(h)[0]
        shown = h if len(h) <= 24 else h[:23] + "…"
        t.add_row(shown, label, ui.Text(f"-m {hc}" if hc else "-", style=ui.ORANGE),
                  ui.Text(f"--format={john}" if john else "-", style=ui.ORANGE))
    ui.panel("Hashes", "el candidato más probable de cada uno", [t], border=ui.ORANGE)


def cmd_hash(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="tarascan hash",
        description="identifica un hash y da el modo de Hashcat/John (acepta tubería)",
    )
    p.add_argument("hash", nargs="?", help="el hash a identificar (o por stdin: cat hashes.txt | tarascan hash)")
    args = p.parse_args(argv)

    if args.hash:
        _hash_detallado(args.hash.strip())
        return 0

    lines = _stdin_lines()
    if not lines:
        ui.error("falta el hash: pásalo como argumento o por tubería (cat hashes.txt | tarascan hash)")
        return 1
    if len(lines) == 1:
        _hash_detallado(lines[0])
    else:
        _hash_tabla(lines)
    return 0


# --------------------------------------------------------------------------- #
# decode
# --------------------------------------------------------------------------- #
def _try_base64(s: str) -> str | None:
    s2 = s.strip()
    if len(s2) < 4 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", s2):
        return None
    try:
        raw = base64.b64decode(s2 + "=" * (-len(s2) % 4), validate=False)
        txt = raw.decode("utf-8")
        if txt and txt.isprintable():
            return txt
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass
    return None


def _try_hex(s: str) -> str | None:
    s2 = re.sub(r"[\s:]", "", s.strip())
    if len(s2) >= 4 and len(s2) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s2):
        try:
            txt = bytes.fromhex(s2).decode("utf-8")
            if txt.isprintable():
                return txt
        except (ValueError, UnicodeDecodeError):
            pass
    return None


def _try_url(s: str) -> str | None:
    if "%" in s:
        dec = urllib.parse.unquote(s)
        if dec != s:
            return dec
    return None


def _try_rot13(s: str) -> str | None:
    if re.search(r"[A-Za-z]", s):
        return codecs.encode(s, "rot_13")
    return None


def _try_binary(s: str) -> str | None:
    bits = re.sub(r"\s", "", s.strip())
    if len(bits) >= 8 and len(bits) % 8 == 0 and re.fullmatch(r"[01]+", bits):
        try:
            txt = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)).decode("utf-8")
            if txt.isprintable():
                return txt
        except (ValueError, UnicodeDecodeError):
            pass
    return None


def _try_html(s: str) -> str | None:
    if "&" in s and ";" in s:
        dec = html.unescape(s)
        if dec != s:
            return dec
    return None


def _try_timestamp(s: str) -> str | None:
    s2 = s.strip()
    if re.fullmatch(r"\d{9,13}", s2):
        val = int(s2)
        if len(s2) == 13:  # milisegundos
            val //= 1000
        try:
            return datetime.datetime.fromtimestamp(val, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OverflowError, OSError):
            pass
    return None


# ROT13 va aparte: no entra en la cascada porque "cambiaría" cualquier texto ya
# legible (daría falsos positivos encadenándose sobre la respuesta buena).
_DECODERS = [
    ("Base64", _try_base64),
    ("Hex", _try_hex),
    ("URL-encode", _try_url),
    ("Entidades HTML", _try_html),
    ("Binario", _try_binary),
    ("Timestamp Unix", _try_timestamp),
]


def decode_cascade(s: str, max_depth: int = 6, allow_rot13: bool = True) -> list[tuple[str, str]]:
    """Decodifica en cascada; devuelve [(codificación, resultado), ...].
    ROT13 solo como último recurso si allow_rot13 (se apaga para hashes)."""
    layers: list[tuple[str, str]] = []
    current = s
    for _ in range(max_depth):
        advanced = False
        for name, fn in _DECODERS:
            out = fn(current)
            if out and out != current:
                layers.append((name, out))
                current = out
                advanced = True
                break
        if not advanced:
            break
    if not layers and allow_rot13:
        rot = _try_rot13(s)
        if rot and rot != s:
            layers.append(("ROT13", rot))
    return layers


def cmd_decode(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="tarascan decode",
        description="decodificador en cascada (acepta tubería)",
    )
    p.add_argument("data", nargs="?", help="la cadena a decodificar (o por stdin: echo ... | tarascan decode)")
    args = p.parse_args(argv)

    data = _arg_or_stdin(args.data)
    if not data:
        ui.error("falta la cadena: pásala como argumento o por tubería (echo ... | tarascan decode)")
        return 1

    ui.rule("decodificar en cascada")

    # Enlaces cruzados: si es otra cosa, manda al subcomando que toca.
    stripped = data.strip()
    looks_hash = bool(re.fullmatch(r"[0-9a-fA-F]{16,128}", stripped)) or stripped.startswith("$")
    if re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", stripped):
        ui.console.print(f"[{ui.ORANGE}]→ parece un JWT; para desglosarlo:[/] [{ui.PURPLE}]tarascan jwt {stripped[:24]}…[/]\n")

    # Para un hash no tiene sentido el ROT13 de respaldo (solo daría ruido).
    layers = decode_cascade(data, allow_rot13=not looks_hash)
    if not layers:
        body = [ui.Text("sin cambios", style=ui.GREY)]
        if looks_hash:
            body.append(ui.note("esto parece un hash, no una codificación: prueba 'tarascan hash'."))
        ui.panel("Decode", "no se reconoció ninguna codificación habitual", body)
        return 0
    body = []
    for i, (name, out) in enumerate(layers, 1):
        body.append(ui.Text(f"{i}. {name}", style=ui.PURPLE))
        body.append(ui.Text(f"   {out}"))
    body.append(ui.note(f"resultado final: {layers[-1][1]}"))
    ui.panel("Decode", f"{len(layers)} capa(s) resuelta(s)", body, border=ui.ORANGE)
    return 0


# --------------------------------------------------------------------------- #
# jwt
# --------------------------------------------------------------------------- #
def _b64url(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def cmd_jwt(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="tarascan jwt",
        description="desglosa un JWT y avisa de problemas (acepta tubería)",
    )
    p.add_argument("token", nargs="?", help="el token JWT (o por stdin)")
    args = p.parse_args(argv)

    token = _arg_or_stdin(args.token)
    if not token:
        ui.error("falta el token: pásalo como argumento o por tubería")
        return 1

    ui.rule("desglose de JWT")
    token = token.strip()
    parts = token.split(".")
    if len(parts) < 2:
        ui.error("no parece un JWT (faltan los puntos separadores)")
        return 1

    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        ui.error(f"no se pudo decodificar el JWT: {exc}")
        return 1

    ui.panel("Header", "cabecera del token", [ui.Text(json.dumps(header, indent=2, ensure_ascii=False))], border=ui.PURPLE)
    ui.panel("Payload", "claims del token", [ui.Text(json.dumps(payload, indent=2, ensure_ascii=False))], border=ui.PURPLE)

    alerts = []
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        alerts.append(ui.warn("alg=none: el token no está firmado, puedes forjarlo a tu gusto."))
    elif alg.startswith("hs"):
        alerts.append(ui.note("alg HMAC (HSxxx): si filtran el secreto, se puede firmar cualquier token; prueba a crackearlo (hashcat -m 16500)."))
    elif alg.startswith(("rs", "es", "ps")):
        alerts.append(ui.note(f"alg asimétrico ({alg.upper()}): prueba alg-confusion — si el server valida HS256 "
                              "usando la clave pública como secreto, puedes forjar tokens con ella."))

    now = datetime.datetime.now(datetime.timezone.utc)
    for claim in ("exp", "iat", "nbf"):
        if claim in payload and isinstance(payload[claim], (int, float)):
            dt = datetime.datetime.fromtimestamp(payload[claim], datetime.timezone.utc)
            label = {"exp": "expira", "iat": "emitido", "nbf": "válido desde"}[claim]
            if claim == "exp":
                estado = "CADUCADO" if dt < now else "vigente"
                style = ui.warn if dt < now else ui.note
                alerts.append(style(f"exp: {dt:%Y-%m-%d %H:%M:%S UTC} ({estado})"))
            else:
                alerts.append(ui.dim(f"{label}: {dt:%Y-%m-%d %H:%M:%S UTC}"))

    sensibles = [k for k in payload if re.search(r"pass|secret|key|token|ssn|card|cvv", k, re.I)]
    if sensibles:
        alerts.append(ui.warn(f"claims con pinta sensible en claro: {', '.join(sensibles)}"))

    if alerts:
        ui.panel("Análisis", "lo que conviene mirar del token", alerts, border=ui.ORANGE)
    return 0

"""Análisis de cabeceras HTTP y métodos permitidos, con la stdlib (sin binario extra).

Revisa qué cabeceras de seguridad faltan y qué métodos HTTP admite el servidor
(destacando los peligrosos como PUT/DELETE/TRACE).
"""

import ssl
import urllib.error
import urllib.request

# Cabeceras de seguridad que se esperan en un servidor bien configurado.
_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (fuerza HTTPS)",
    "content-security-policy": "CSP (mitiga XSS/inyección)",
    "x-frame-options": "X-Frame-Options (anti-clickjacking)",
    "x-content-type-options": "X-Content-Type-Options (anti MIME-sniffing)",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}
# Cabeceras que, si están, filtran información del stack.
_LEAKY_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")
_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

_TIMEOUT = 10
# Muchos objetivos de laboratorio usan certificados autofirmados; no verificamos.
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _request(url: str, method: str):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "tarascan"})
    return urllib.request.urlopen(req, timeout=_TIMEOUT, context=_CTX)


def scan(url: str) -> dict:
    present: dict[str, str] = {}
    try:
        with _request(url, "GET") as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()}
    # urllib.error.URLError (conexión) sube y la captura _run como fallo.

    missing = [desc for h, desc in _SECURITY_HEADERS.items() if h not in headers]
    leaks = {h: headers[h] for h in _LEAKY_HEADERS if h in headers}

    methods: list[str] = []
    try:
        with _request(url, "OPTIONS") as resp:
            allow = resp.getheader("Allow", "")
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        pass
    dangerous = [m for m in methods if m in _DANGEROUS_METHODS]

    return {
        "missing": missing,
        "leaks": leaks,
        "methods": methods,
        "dangerous_methods": dangerous,
    }

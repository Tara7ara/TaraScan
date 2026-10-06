"""Enum web: descubre swagger/openapi/graphql (con introspección) y audita CORS."""

import argparse
import json
import secrets
import ssl
import urllib.error
import urllib.request

from tarascan import store, ui


def _alert_lines(*bodies) -> list[str]:
    """Saca las líneas de interpretación (las que empiezan por '→') de los cuerpos
    de los paneles, para guardarlas como hallazgos en el store."""
    out: list[str] = []
    for body in bodies:
        for item in body or []:
            for ln in getattr(item, "plain", str(item)).splitlines():
                ln = ln.strip()
                if ln.startswith("→"):
                    out.append(ln[1:].strip())
    return out


def _persist_web(base: str, apis: list, cors: list, gql: list | None) -> None:
    """Deja constancia del escaneo web en el store para que `report` lo recoja."""
    from urllib.parse import urlparse

    host = urlparse(base).hostname or base
    findings = []
    for ln in _alert_lines(apis, cors):
        marca = "[!] " if ("credenciales" in ln.lower() or "introspección" in ln.lower()) else ""
        findings.append(f"{marca}web ({base}): {ln}")
    if gql:
        findings.append(f"[!] web ({base}): introspección GraphQL abierta, el esquema se vuelca entero")
    resumen = f"{base}: " + (f"{len(findings)} hallazgo(s)" if findings else "sin hallazgos destacables")
    try:
        store.record_scan(host, findings=findings or None, scans={"web": {"resumen": resumen}})
    except Exception:  # noqa: BLE001 - persistir no debe tumbar el comando
        pass

_UA = "Mozilla/5.0 (tarascan web)"
_API_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/v2/api-docs", "/v3/api-docs",
    "/openapi.json", "/openapi.yaml", "/api/swagger.json", "/api-docs",
    "/swagger-ui.html", "/swagger/index.html", "/graphql", "/api/graphql",
    "/.well-known/openid-configuration", "/api/v1/", "/api/",
]
_SEC_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}
_INTROSPECTION = '{"query":"{__schema{types{name}}}"}'


def _ctx() -> ssl.SSLContext:
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _get(url: str, data: bytes | None = None, headers: dict | None = None):
    h = {"User-Agent": _UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method="POST" if data else "GET")
    return urllib.request.urlopen(req, timeout=15, context=_ctx())


def _fetch(url: str, data: bytes | None = None, headers: dict | None = None):
    """Devuelve (status, content-type, longitud, snippet del cuerpo) o None."""
    try:
        resp = _get(url, data=data, headers=headers)
        ctype = resp.headers.get("Content-Type", "")
        body = resp.read(8192)
        return resp.status, ctype, len(body), body[:2048].decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(8192)
        except Exception:  # noqa: BLE001
            raw = b""
        ctype = exc.headers.get("Content-Type", "") if exc.headers else ""
        return exc.code, ctype, len(raw), raw[:2048].decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None


# Firmas de una API/doc real en el cuerpo, por si la sirven con content-type
# equivocado (p.ej. swagger.json como text/html).
_API_SIGNATURES = ('"swagger"', '"openapi"', '"paths"', '"__schema"', 'swagger-ui', '"basePath"')


def _looks_like_api(ctype: str, snippet: str = "") -> bool:
    c = ctype.lower()
    if any(t in c for t in ("json", "yaml", "yml")):
        return True
    low = snippet.lower()
    return any(sig in low for sig in _API_SIGNATURES)


def _probe_apis(base: str) -> list:
    body = []
    root = base.rstrip("/")

    # Línea base: una ruta aleatoria que no debería existir. Si responde <400,
    # el servidor es catch-all (todo da 200) y no podemos fiarnos del status.
    baseline = _fetch(f"{root}/{secrets.token_hex(12)}.tarascan404")
    catch_all = baseline is not None and baseline[0] < 400
    base_sig = (baseline[0], baseline[2]) if baseline else None
    if catch_all:
        body.append(ui.note("el servidor responde <400 a rutas inexistentes (catch-all): "
                            "solo marco lo que de verdad parece una API (JSON/YAML) o difiere de la base."))

    found = False
    for path in _API_PATHS:
        res = _fetch(root + path)
        if res is None:
            continue
        status, ctype, length, snippet = res
        if status >= 400:
            continue
        es_api = _looks_like_api(ctype, snippet)
        # Con catch-all, solo cuenta si parece API de verdad o difiere de la base.
        if catch_all and not es_api and (status, length) == base_sig:
            continue
        found = True
        tag = " [API real]" if es_api else ""
        linea = ui.status(status)
        linea.append(f"  {path}  ({ctype or 'sin tipo'}, {length}B)")
        if tag:
            linea.append(tag, style=ui.ORANGE)
        body.append(linea)

    if not found:
        msg = "sin rutas de API/docs que destaquen sobre la respuesta base" if catch_all else "sin rutas de API/docs habituales accesibles"
        body.append(ui.Text(msg, style=ui.GREY))
    else:
        body.append(ui.note("revisa los endpoints accesibles: pueden exponer el esquema o métodos sin auth."))
    return body


def _graphql_introspection(base: str) -> list | None:
    for path in ("/graphql", "/api/graphql", "/v1/graphql"):
        url = base.rstrip("/") + path
        try:
            resp = _get(url, data=_INTROSPECTION.encode(), headers={"Content-Type": "application/json"})
            raw = resp.read().decode("utf-8", "replace")
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError):
            continue
        try:
            data = json.loads(raw)
        except ValueError:
            continue
        types = (((data.get("data") or {}).get("__schema") or {}).get("types")) or []
        if types:
            names = [t.get("name") for t in types if t.get("name") and not t["name"].startswith("__")]
            return [
                ui.warn(f"introspección ABIERTA en {path}: el esquema se vuelca entero."),
                ui.Text(f"{len(names)} tipo(s): " + ", ".join(names[:40]) + ("…" if len(names) > 40 else "")),
            ]
    return None


def _headers_and_cors(base: str) -> list:
    body = []
    try:
        resp = _get(base)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as exc:
        return [ui.Text(f"no se pudo leer cabeceras: {exc}", style=ui.GREY)]
    missing = [d for h, d in _SEC_HEADERS.items() if h not in hdrs]
    if missing:
        body.append(ui.warn("faltan cabeceras: " + ", ".join(missing)))
    else:
        body.append(ui.dim("cabeceras de seguridad básicas presentes."))
    # CORS: pedimos con un Origin malicioso y vemos si lo refleja.
    try:
        resp = _get(base, headers={"Origin": "https://evil.example"})
        ch = {k.lower(): v for k, v in resp.headers.items()}
        acao = ch.get("access-control-allow-origin")
        acac = ch.get("access-control-allow-credentials")
        if acao == "https://evil.example":
            msg = "CORS refleja cualquier Origin"
            if acac == "true":
                msg += " CON credenciales: robo de datos autenticados entre orígenes."
            body.append(ui.warn(msg))
        elif acao == "*":
            body.append(ui.note("CORS Access-Control-Allow-Origin: * (abierto, pero sin credenciales)."))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError):
        pass
    if "server" in hdrs:
        body.append(ui.dim(f"Server: {hdrs['server']}"))
    if "x-powered-by" in hdrs:
        body.append(ui.dim(f"X-Powered-By: {hdrs['x-powered-by']}"))
    return body


def cmd_web(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="tarascan web", description="enumeración web quirúrgica (APIs, GraphQL, CORS)")
    p.add_argument("url", help="URL objetivo (p.ej. http://10.10.10.10:8080)")
    args = p.parse_args(argv)

    base = args.url.strip()
    if not base.startswith(("http://", "https://")):
        # Sin esquema: deduce https si el puerto es de TLS (443/8443), si no http.
        host_part = base.split("/", 1)[0]
        port = host_part.rsplit(":", 1)[-1] if ":" in host_part else ""
        scheme = "https" if port in ("443", "8443") else "http"
        base = f"{scheme}://{base}"
    ui.rule(f"web · [{ui.PURPLE}]{ui.escape(base)}[/]")

    with ui.console.status(f"[{ui.ORANGE}]buscando APIs y docs[/][{ui.GREY}]…[/]", spinner="dots"):
        apis = _probe_apis(base)
    ui.panel("APIs y documentación", "busca documentación de API expuesta (Swagger/OpenAPI/GraphQL)", apis)

    with ui.console.status(f"[{ui.ORANGE}]probando introspección GraphQL[/][{ui.GREY}]…[/]", spinner="dots"):
        gql = _graphql_introspection(base)
    if gql:
        ui.panel("GraphQL", "volcado del esquema por introspección", gql, border="red")

    with ui.console.status(f"[{ui.ORANGE}]auditando cabeceras y CORS[/][{ui.GREY}]…[/]", spinner="dots"):
        cors = _headers_and_cors(base)
    ui.panel("Cabeceras y CORS", "comprueba cabeceras defensivas que faltan y la política CORS", cors)

    _persist_web(base, apis, cors, gql)
    return 0

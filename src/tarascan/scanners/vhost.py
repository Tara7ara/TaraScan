"""Enumeración de vhosts por cabecera Host.

Muchos servidores (y sobre todo los reverse-proxy como nginx-proxy-manager)
sirven sitios distintos según la cabecera Host. Escaneando por IP solo se ve el
sitio por defecto; probando distintos Host se descubren los demás.
"""

import ssl
import urllib.error
import urllib.request

_TIMEOUT = 8
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

# Nombres habituales de vhosts; con un dominio se prueban como <nombre>.<dominio>.
_CANDIDATES = [
    "www", "mail", "admin", "dev", "staging", "test", "api", "portal",
    "intranet", "git", "gitlab", "grafana", "jenkins", "wiki", "blog", "shop",
    "app", "cloud", "vpn", "internal", "dashboard", "monitor", "status",
    "webmail", "cpanel", "dev", "beta", "old", "backup",
]


def _fetch(url: str, host: str):
    """Devuelve (status, longitud) de la respuesta usando esa cabecera Host, o None."""
    req = urllib.request.Request(url, headers={"Host": host, "User-Agent": "tarascan"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=_CTX) as resp:
            return resp.status, len(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, len(exc.read())
        except Exception:
            return exc.code, 0
    except (urllib.error.URLError, OSError, ValueError):
        return None


def scan(url: str, domain: str | None = None, wordlist: str | None = None) -> list[dict]:
    names = list(_CANDIDATES)
    if domain:
        names = [f"{c}.{domain}" for c in _CANDIDATES] + [domain]
    if wordlist:
        try:
            with open(wordlist, encoding="utf-8", errors="ignore") as fh:
                names = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError:
            pass

    # Dos líneas base con Hosts inexistentes distintos. Muchos servidores
    # (WordPress y otros) reflejan el Host en la página, así que el tamaño varía
    # un poco con cada Host aunque sirvan el MISMO sitio: eso son falsos
    # positivos. La diferencia entre las dos bases mide ese "ruido"; solo
    # contamos como vhost real lo que difiera bastante más que eso.
    base1 = _fetch(url, "tarascan-vhost-probe-aaa.invalid")
    base2 = _fetch(url, "tarascan-vhost-probe-bbbbbbbbbbbbbbb.invalid")
    if base1 is None or base2 is None:
        return []

    # Si el servidor refleja el Host, el tamaño cambia unas decenas de bytes con
    # cada nombre (las dos sondas, de longitudes distintas, lo miden). Un vhost
    # real sirve OTRO sitio y difiere muchísimo más, así que exigimos que la
    # diferencia supere un porcentaje del tamaño (y un mínimo absoluto).
    noise = abs(base1[1] - base2[1])
    threshold = max(512, noise * 4, int(base1[1] * 0.10))

    found = []
    seen = set()
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        r = _fetch(url, name)
        if r is None:
            continue
        status, length = r
        # Distinto de verdad: otro código, o un tamaño que se sale del ruido.
        if status != base1[0] or abs(length - base1[1]) > threshold:
            found.append({"host": name, "status": str(status), "size": str(length)})

    return found

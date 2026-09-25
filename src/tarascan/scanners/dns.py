"""Recon de DNS: registros, transferencia de zona (AXFR) y fuerza bruta de subdominios (dnspython)."""

import dns.exception
import dns.query
import dns.resolver
import dns.zone

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")

# Lista corta de subdominios habituales para el brute por defecto; se puede
# ampliar con una wordlist de seclists si se pasa por parámetro.
_COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "dns", "vpn", "remote", "portal", "admin", "test", "dev", "staging",
    "api", "cdn", "cpanel", "webdisk", "autodiscover", "m", "blog", "shop",
    "git", "gitlab", "jenkins", "jira", "intranet", "app", "cloud", "db",
]


def scan(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    records: dict[str, list[str]] = {}
    for rtype in _RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        values = [rdata.to_text().strip('"') for rdata in answers]
        if values:
            records[rtype] = values

    return records


def zone_transfer(domain: str) -> dict:
    """Intenta un AXFR contra cada NS del dominio. Devuelve {ns: [nombres]} si algún NS lo permite."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        nameservers = [rdata.to_text().rstrip(".") for rdata in resolver.resolve(domain, "NS")]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return {}

    leaked: dict[str, list[str]] = {}
    for ns in nameservers:
        try:
            ns_ip = resolver.resolve(ns, "A")[0].to_text()
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=8.0))
        except (dns.exception.DNSException, ConnectionError, OSError, EOFError):
            # EOFError: el NS cierra la conexión al rechazar el AXFR (lo normal).
            continue
        names = sorted(name.to_text() for name in zone.nodes.keys())
        if names:
            leaked[ns] = names

    return leaked


def brute_subdomains(domain: str, wordlist: str | None = None) -> list[dict]:
    """Resuelve subdominios habituales (o los de una wordlist) y devuelve los que existen."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0

    names = _COMMON_SUBDOMAINS
    if wordlist:
        try:
            with open(wordlist, encoding="utf-8", errors="ignore") as fh:
                names = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except OSError:
            pass

    # Detección de wildcard: si un subdominio aleatorio (que no debería existir)
    # resuelve, el dominio tiene DNS comodín y todo resolvería a la misma IP —
    # esas respuestas son ruido, no subdominios reales. Nos quedamos solo con los
    # que apunten a una IP distinta de la del comodín.
    wildcard_ips: set[str] = set()
    try:
        probe = resolver.resolve(f"tarascan-wildcard-probe-zzq.{domain}", "A")
        wildcard_ips = {rdata.to_text() for rdata in probe}
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass

    found = []
    for sub in names:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        ip = answers[0].to_text()
        if ip in wildcard_ips:
            continue
        found.append({"host": fqdn, "ip": ip})

    return found

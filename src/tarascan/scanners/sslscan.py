"""Wrapper sobre sslscan: protocolos TLS habilitados, cifrados débiles y datos del certificado."""

import subprocess
import xml.etree.ElementTree as ET

# Protocolos que ya no deberían estar habilitados.
_INSECURE_PROTOCOLS = {("ssl", "2"), ("ssl", "3"), ("tls", "1.0"), ("tls", "1.1")}


def scan(target: str, port: str = "443") -> dict:
    result = subprocess.run(
        ["sslscan", "--no-colour", f"--xml=-", f"{target}:{port}"],
        capture_output=True,
        text=True,
        check=True,
    )

    root = ET.fromstring(result.stdout)
    test = root.find("ssltest")
    if test is None:
        return {"protocols": [], "insecure_protocols": [], "weak_ciphers": [], "cert": {}}

    protocols, insecure = [], []
    for proto in test.findall("protocol"):
        if proto.get("enabled") != "1":
            continue
        label = f"{proto.get('type', '').upper()}v{proto.get('version', '')}"
        protocols.append(label)
        if (proto.get("type"), proto.get("version")) in _INSECURE_PROTOCOLS:
            insecure.append(label)

    # Cifrados marcados por sslscan como débiles/inseguros (strength distinta de "acceptable"/"strong").
    weak_ciphers = []
    for cipher in test.findall("cipher"):
        strength = cipher.get("strength", "")
        if strength in ("null", "weak", "insecure"):
            weak_ciphers.append(f"{cipher.get('cipher', '')} ({strength})")

    cert = {}
    cert_el = test.find("certificate") or test.find("certificates/certificate")
    if cert_el is not None:
        subject = cert_el.findtext("subject")
        expired = cert_el.findtext("expired")
        sig = cert_el.findtext("signature-algorithm")
        not_after = cert_el.findtext("not-valid-after")
        if subject:
            cert["subject"] = subject
        if sig:
            cert["firma"] = sig
        if not_after:
            cert["caduca"] = not_after
        if expired == "true":
            cert["estado"] = "CADUCADO"

    return {
        "protocols": protocols,
        "insecure_protocols": insecure,
        "weak_ciphers": weak_ciphers,
        "cert": cert,
    }

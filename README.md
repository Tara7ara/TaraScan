# TaraScan

Wrapper en Python que encadena herramientas de recon ya instaladas y unifica su salida en algo legible, en vez de ir lanzando cada herramienta suelta y leyendo formatos distintos.

> Úsalo solo contra objetivos propios o con autorización explícita.

## Estado

En desarrollo, pero ya cubre de sobra el recon de Fase 1 (red, web y SMB). La salida es por terminal; la exportación a Markdown llegará más adelante.

Las herramientas se lanzan **en paralelo** y la salida va apareciendo por bloques según terminan, siempre en el mismo orden. Mientras una herramienta lenta (nmap NSE, nuclei) sigue trabajando, se muestra un spinner para que se vea que no está colgado.

## Requisitos

- Python 3.11+ (la dependencia `dnspython` se instala sola).
- **nmap** es el único imprescindible: es el punto de partida y decide qué más se lanza.
- El resto son opcionales; si una no está en el PATH, esa sección avisa y el escaneo sigue:
  - Web: `whatweb`, `gobuster`, `ffuf`, `nikto`, `nuclei`, `wafw00f`, `sslscan`, `wpscan`, `feroxbuster`.
  - Red/SMB: `smbclient`, `enum4linux`, `nbtscan`, `netexec` (binario `nxc`).
  - SNMP: `snmpwalk` (paquete `net-snmp`), `onesixtyone`.
  - Otros: `searchsploit` (exploit-db), `nc`, `subfinder`, `sqlmap`, `hydra`.

Notas:
- `nuclei` necesita descargar sus plantillas la primera vez: `nuclei -update-templates`.
- `gobuster`, `ffuf` y `onesixtyone` usan wordlists de `seclists` por defecto.
- `netexec` va mejor instalado con pipx (`pipx install git+https://github.com/Pennyw0rth/NetExec`) que desde bundles empaquetados.

## Instalación

```
pipx install .
```

Para desarrollo (modo editable):

```
pip install --user --break-system-packages -e .
```

## Uso

```
tarascan <dominio-o-ip>
```

Opciones:

- `--deep` — descubrimiento de contenido web recursivo con feroxbuster (más lento que gobuster, va fuera de la cadena por defecto).
- `--sqli` — lanza sqlmap contra la web detectada. **Intrusivo.**
- `--brute SERVICIO` — fuerza bruta de credenciales con hydra para ese servicio (`ssh`, `ftp`, `http-get`...). **Intrusivo, puede bloquear cuentas.**

## Qué hace

A partir de un escaneo de nmap (con detección de versión), encadena el resto según lo que encuentre:

- **DNS** (solo si el objetivo es un dominio): registros A/MX/NS/TXT..., intento de transferencia de zona (AXFR), fuerza bruta de subdominios habituales (con detección de wildcard) y subdominios pasivos por OSINT (`subfinder`).
- **Siempre**: `searchsploit` busca exploits conocidos para cada servicio+versión detectado; los scripts NSE de nmap (`default` + `vuln` seguros) sobre los puertos abiertos; y una comprobación de SNMP (`onesixtyone` + `snmpwalk`), ya que 161/udp no aparece en el escaneo TCP.
- **Web** (si hay un puerto con servicio "http"): `whatweb`, `wafw00f` (detección de WAF), análisis de cabeceras de seguridad y métodos HTTP, `gobuster` (directorios), `ffuf` (archivos sensibles/backups), `nikto`, `nuclei` (vulnerabilidades por plantillas) y, si `whatweb` detecta WordPress, `wpscan`.
- **TLS** (en cada puerto HTTPS): `sslscan` — protocolos habilitados marcando los inseguros, cifrados débiles y datos del certificado.
- **SMB** (si hay 139/445): `smbclient`, `enum4linux`, `nbtscan` y `netexec` (sesión nula).

Al final siempre se imprime un **Resumen** en lenguaje llano: puertos abiertos, si hay web/SMB, hallazgos por herramienta y avisos marcados con `[!]` para lo más serio (TLS inseguro, métodos peligrosos, AXFR permitido, SNMP con comunidad válida...).

## Salida de ejemplo

```
── tarascan · recon sobre scanme.nmap.org ──

nmap — puertos abiertos
┏━━━━━━━━┳━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Puerto ┃ Proto ┃ Servicio ┃ Versión               ┃
┡━━━━━━━━╇━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ 22     │ tcp   │ ssh      │ OpenSSH 6.6.1p1       │
│ 80     │ tcp   │ http     │ Apache httpd 2.4.7    │
└────────┴───────┴──────────┴───────────────────────┘

searchsploit — exploits conocidos (exploit-db)
┏━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Puerto ┃ EDB-ID ┃ Tipo   ┃ Título                                ┃
┡━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 22     │ 45233  │ remote │ OpenSSH 2.3 < 7.7 - User Enumeration   │
└────────┴────────┴────────┴───────────────────────────────────────┘

wafw00f — detección de WAF
  sin WAF detectado

http — cabeceras de seguridad y métodos
  server: Apache/2.4.7 (Ubuntu)
  cabeceras de seguridad ausentes: 6
    - HSTS (fuerza HTTPS)
    - CSP (mitiga XSS/inyección)
    ...

nuclei — vulnerabilidades por plantillas
┏━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Severidad ┃ Plantilla  ┃ Nombre           ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ medium    │ ...        │ ...              │
└───────────┴────────────┴──────────────────┘

Resumen
  • 2 puerto(s) abierto(s)
  • searchsploit encontró 1 exploit(s) potencial(es)
  • web detectada en el puerto 80 (http://scanme.nmap.org)
  • faltan 6 cabecera(s) de seguridad
  • nuclei: 1 hallazgo(s)
```

## Herramientas encadenadas

| Fase | Herramientas |
|------|--------------|
| Red / puertos | nmap (con versión y scripts NSE), nc (banners), searchsploit |
| DNS (dominios) | dnspython (registros, AXFR, subdominios), subfinder |
| Web | whatweb, wafw00f, cabeceras HTTP, gobuster, ffuf, nikto, nuclei, wpscan, feroxbuster (`--deep`) |
| TLS | sslscan |
| SMB | smbclient, enum4linux, nbtscan, netexec |
| SNMP | onesixtyone, snmpwalk |
| Intrusivas (opt-in) | sqlmap (`--sqli`), hydra (`--brute`) |

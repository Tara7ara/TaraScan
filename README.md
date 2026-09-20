# TaraScan

Wrapper en Python que encadena herramientas de recon ya instaladas y unifica su salida en algo legible, en vez de ir lanzando cada herramienta suelta y leyendo formatos distintos.

> Úsalo solo contra objetivos propios o con autorización explícita.

## Estado

En desarrollo. Fase 1: recon de dominios/subdominios. La salida es por terminal; una exportación a Markdown llegará más adelante.

## Requisitos

- Python 3.11+
- nmap, gobuster, whatweb, ffuf, nikto, smbclient y enum4linux instalados y accesibles en el PATH
- `wpscan` si quieres el análisis extra cuando se detecta WordPress

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

Salida de ejemplo:

```
── tarascan · recon sobre scanme.nmap.org ──

nmap — puertos abiertos
┏━━━━━━━━┳━━━━━━━┳━━━━━━━━━━┓
┃ Puerto ┃ Proto ┃ Servicio ┃
┡━━━━━━━━╇━━━━━━━╇━━━━━━━━━━┩
│ 22     │ tcp   │ ssh      │
│ 80     │ tcp   │ http     │
└────────┴───────┴──────────┘

whatweb — tecnologías detectadas
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Plugin     ┃ Detalle       ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ HTTPServer │ nginx/1.24.0  │
│ Title      │ Bienvenido    │
└────────────┴───────────────┘

gobuster — rutas encontradas
┏━━━━━━━━┳━━━━━━━━┓
┃ Ruta   ┃ Status ┃
┡━━━━━━━━╇━━━━━━━━┩
│ /admin │ 301    │
└────────┴────────┘

ffuf — archivos sensibles/backups
┏━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┓
┃ Ruta        ┃ Status ┃ Tamaño ┃
┡━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━┩
│ /backup.zip │ 200    │ 8214   │
└─────────────┴────────┴────────┘

nikto — configuración/vulnerabilidades web
  - 6 cabeceras de seguridad recomendadas ausentes: content-security-policy,
    strict-transport-security, x-content-type-options, referrer-policy,
    permissions-policy, x-frame-options

enum4linux — enumeración SMB
  Usuarios
    - testuser (RID 0x3e8)
  Recursos compartidos
    - public          Disk

Resumen
  • 3 puerto(s) abierto(s)
  • web detectada en el puerto 80 (http://scanme.nmap.org)
  • gobuster encontró 1 ruta(s)
  • ffuf encontró 1 archivo(s) sensible(s)/backup(s)
  • nikto reportó 1 hallazgo(s) de configuración
```

Si nmap detecta un puerto web (servicio con "http" en el nombre), se lanzan automáticamente contra ese puerto: `whatweb` (fingerprinting), `gobuster` (directorios, wordlist `common.txt` de seclists), `ffuf` (fuzzing de una lista de archivos sensibles/backups habituales — `.env`, `backup.zip`, `wp-config.php.bak`...) y `nikto` (configuración/vulnerabilidades web básicas, resumida — las cabeceras de seguridad ausentes salen agrupadas en una línea en vez de repetidas). Si `whatweb` detecta WordPress, se añade `wpscan`.

Si nmap detecta puerto 139 o 445 (SMB), se lanzan `smbclient` (listado de recursos compartidos sin autenticación) y `enum4linux` (enumeración de SO, shares y usuarios, agrupada por secciones).

Al final siempre se imprime un **Resumen** con lo esencial en lenguaje llano: puertos abiertos, si hay web/SMB, y cuántos hallazgos encontró cada herramienta.

## Herramientas encadenadas

- nmap (puertos abiertos)
- whatweb (tecnologías del servidor web, solo si hay puerto http)
- gobuster (rutas web con wordlist genérica, solo si hay puerto http)
- ffuf (archivos sensibles/backups habituales, solo si hay puerto http)
- nikto (configuración/vulnerabilidades web básicas, solo si hay puerto http)
- wpscan (solo si whatweb detecta WordPress)
- smbclient y enum4linux (recursos SMB y enumeración básica, solo si hay puerto 139/445)

# TaraScan

Wrapper en Python que encadena herramientas de recon ya instaladas y unifica su salida en algo legible, en vez de ir lanzando cada herramienta suelta y leyendo formatos distintos.

> Úsalo solo contra objetivos propios o con autorización explícita.

## Estado

En desarrollo. Fase 1: recon de dominios/subdominios. La salida es por terminal; una exportación a Markdown llegará más adelante.

## Requisitos

- Python 3.11+
- nmap, gobuster, whatweb y ffuf instalados y accesibles en el PATH

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
```

Si nmap detecta un puerto web (servicio con "http" en el nombre), se lanzan automáticamente contra ese puerto: `whatweb` (fingerprinting), `gobuster` (directorios, wordlist `common.txt` de seclists) y `ffuf` (fuzzing de una lista de archivos sensibles/backups habituales — `.env`, `backup.zip`, `wp-config.php.bak`...).

## Herramientas encadenadas

- nmap (puertos abiertos)
- whatweb (tecnologías del servidor web, solo si hay puerto http)
- gobuster (rutas web con wordlist genérica, solo si hay puerto http)
- ffuf (archivos sensibles/backups habituales, solo si hay puerto http)

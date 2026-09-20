# TaraScan

Wrapper en Python que encadena herramientas de recon ya instaladas y unifica su salida en algo legible, en vez de ir lanzando cada herramienta suelta y leyendo formatos distintos.

> Úsalo solo contra objetivos propios o con autorización explícita.

## Estado

En desarrollo. Fase 1: recon de dominios/subdominios. La salida es por terminal; una exportación a Markdown llegará más adelante.

## Requisitos

- Python 3.11+
- nmap y gobuster instalados y accesibles en el PATH

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

gobuster — rutas encontradas
┏━━━━━━━━┳━━━━━━━━┓
┃ Ruta   ┃ Status ┃
┡━━━━━━━━╇━━━━━━━━┩
│ /admin │ 301    │
└────────┴────────┘
```

Si nmap detecta un puerto web (servicio con "http" en el nombre), `gobuster` se lanza automáticamente contra ese puerto con la wordlist `common.txt` de seclists.

## Herramientas encadenadas

- nmap (puertos abiertos)
- gobuster (rutas web, solo si nmap detectó un puerto http)

Más herramientas (ffuf, whatweb...) según avance la Fase 1.

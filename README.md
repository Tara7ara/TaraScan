# TaraScan

Wrapper en Python que encadena herramientas de recon ya instaladas y unifica su salida en algo legible, en vez de ir lanzando cada herramienta suelta y leyendo formatos distintos.

> Úsalo solo contra objetivos propios o con autorización explícita.

## Estado

En desarrollo. Fase 1: recon de dominios/subdominios. La salida es por terminal; una exportación a Markdown llegará más adelante.

## Requisitos

- Python 3.11+
- nmap instalado y accesible en el PATH

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
```

## Herramientas encadenadas

- nmap (puertos abiertos)

Más herramientas (gobuster/ffuf, whatweb...) según avance la Fase 1.

"""Persistencia local por objetivo en ~/.cache/tarascan/ (puertos, hallazgos, historial)."""

import datetime
import json
import os
import re
from pathlib import Path
from typing import Any


def _cache_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME", "").strip()
    root = Path(base) if base else Path.home() / ".cache"
    return root / "tarascan"


def _targets_dir() -> Path:
    return _cache_root() / "targets"


def _state_file() -> Path:
    return _cache_root() / "state.json"


def slug(target: str) -> str:
    """Nombre de fichero seguro para un objetivo (IP, dominio o URL)."""
    s = re.sub(r"^\w+://", "", target.strip())
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    return s or "target"


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_json(path: Path, data: dict) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# Estado por objetivo
# --------------------------------------------------------------------------- #
def load_target(target: str) -> dict:
    """Devuelve el estado guardado del objetivo, o un esqueleto vacío."""
    data = _read_json(_targets_dir() / f"{slug(target)}.json")
    data.setdefault("target", target)
    data.setdefault("ports", [])          # [{port, service, version}]
    data.setdefault("tech", [])           # tecnologías web detectadas
    data.setdefault("findings", [])       # líneas de hallazgo del resumen
    data.setdefault("scans", {})          # herramienta -> {ts, resumen}
    data.setdefault("history", [])        # instantáneas por escaneo, para `diff`
    return data


def save_target(data: dict) -> bool:
    data["updated"] = datetime.datetime.now().isoformat(timespec="seconds")
    return _write_json(_targets_dir() / f"{slug(data['target'])}.json", data)


_HISTORY_MAX = 10


def add_snapshot(target: str, ports: list[dict], tech: list[str] | None = None) -> bool:
    """Guarda una instantánea (puertos+versiones+tecnologías) de este escaneo,
    para que `diff` compare con la anterior. Mantiene las últimas _HISTORY_MAX."""
    data = load_target(target)
    snap = {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "ports": [{"port": p.get("port"), "service": p.get("service", ""),
                   "version": p.get("version", "")} for p in ports if p.get("port")],
        "tech": list(tech or []),
    }
    data["history"].append(snap)
    data["history"] = data["history"][-_HISTORY_MAX:]
    return save_target(data)


def record_scan(target: str, ports: list[dict] | None = None,
                tech: list[str] | None = None, findings: list[str] | None = None,
                scans: dict[str, Any] | None = None) -> bool:
    """Funde lo nuevo con lo que ya hubiera del objetivo (no pisa a ciegas)."""
    data = load_target(target)
    if ports:
        by_port = {x.get("port"): x for x in data["ports"]}
        for p in ports:
            existing = by_port.get(p.get("port"))
            if existing is None:
                data["ports"].append(p)
                by_port[p.get("port")] = p
            else:
                # Merge campo a campo: valor nuevo no vacío gana, si no conserva el viejo.
                for k, v in p.items():
                    if v:
                        existing[k] = v
    if tech:
        for t in tech:
            if t not in data["tech"]:
                data["tech"].append(t)
    if findings:
        for fnd in findings:
            if fnd not in data["findings"]:
                data["findings"].append(fnd)
    if scans:
        for name, info in scans.items():
            data["scans"][name] = {"ts": datetime.datetime.now().isoformat(timespec="seconds"), **info}
    return save_target(data)


def list_targets() -> list[str]:
    d = _targets_dir()
    if not d.is_dir():
        return []
    return sorted(p.stem for p in d.glob("*.json"))


# --------------------------------------------------------------------------- #
# Objetivo y workspace activos (sesión)
# --------------------------------------------------------------------------- #
def get_state() -> dict:
    return _read_json(_state_file())


def set_active_target(target: str) -> bool:
    st = get_state()
    st["active_target"] = target
    return _write_json(_state_file(), st)


def get_active_target() -> str | None:
    return get_state().get("active_target") or None


def set_active_workspace(path: str) -> bool:
    st = get_state()
    st["active_workspace"] = path
    return _write_json(_state_file(), st)


def get_active_workspace() -> str | None:
    return get_state().get("active_workspace") or None

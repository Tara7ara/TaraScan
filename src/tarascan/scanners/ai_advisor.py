"""Análisis con IA del informe de recon.

Opcional y desactivado por defecto. Coge el informe que ya ha generado tarascan
y se lo pasa a un modelo de lenguaje para que devuelva tres cosas: un resumen
real, los hallazgos críticos con su recomendación, y los comandos que tendría
sentido lanzar como siguientes pasos.

Usa un endpoint compatible con la API de OpenAI (por defecto, el gratuito de
NVIDIA en https://integrate.api.nvidia.com/v1). No añade dependencias: habla
con el endpoint por HTTP con la librería estándar.

La clave NUNCA está en el código ni en el repo: se lee de una variable de
entorno. Sin clave, esta función no se usa.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request

# Endpoint y modelo por defecto. Todo se puede cambiar por variable de entorno
# sin tocar el código, por si NVIDIA renombra el modelo o se quiere usar otro
# proveedor compatible con OpenAI (OpenRouter, un Ollama local, etc.).
DEFAULT_BASE = "https://integrate.api.nvidia.com/v1"
DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"

# Cadena de respaldo: si el primero está saturado/no disponible, se prueba el
# siguiente, y así. De más potente a más seguro (todos verificados con respuesta
# limpia en el free tier). TARASCAN_AI_MODEL, si se define, va primero.
_FALLBACK_MODELS = (
    "nvidia/nemotron-3-ultra-550b-a55b",   # el mejor análisis
    "nvidia/nemotron-3-super-120b-a12b",   # fuerte y rápido
    "openai/gpt-oss-20b",                  # ligero y limpio
    "meta/llama-3.2-11b-vision-instruct",  # red de seguridad, siempre responde
)

# Nombres de variable aceptados para la clave, en orden de preferencia.
_KEY_VARS = ("TARASCAN_AI_KEY", "NVIDIA_API_KEY", "OPENAI_API_KEY")

# Si el informe es enorme, lo recortamos: al modelo le basta con lo esencial y
# así no se dispara el gasto de tokens ni se pasa del límite de contexto.
_MAX_CHARS = 24000

# Reintentos cuando el endpoint gratuito está saturado (503/429).
_MAX_RETRIES = 3
_RETRY_WAIT = 4  # segundos; crece en cada reintento

_SYSTEM = (
    "Eres un pentester ofensivo ayudando en un test autorizado y en el estudio "
    "del eJPT. Te paso el informe de recon de la herramienta tarascan sobre un "
    "objetivo con permiso explícito. Tu objetivo es ENCONTRAR Y EXPLOTAR, no "
    "defender: piensa como un atacante. No des consejos de mitigación, parches, "
    "actualizaciones ni hardening; eso no interesa aquí. Responde en español, "
    "conciso y sin relleno, con estas tres secciones y en este orden:\n"
    "## Resumen\n"
    "Qué es el objetivo y qué superficie de ataque ofrece, en 3-5 frases.\n"
    "## Vectores de ataque\n"
    "Lo MÁS IMPORTANTE: básate en los HALLAZGOS CONCRETOS del informe, no en "
    "ideas genéricas. Si el informe dice que SMB permite sesión nula con "
    "escritura, que hay un .env expuesto, que SNMP 'public' responde, que "
    "WordPress tiene xmlrpc/user-enum o que un panel no pide auth, ESO es lo que "
    "hay que explotar; cita el hallazgo exacto. Evita el relleno de 'fuerza "
    "bruta a todo' si no hay indicio de ello. Lista de viñetas, lo más "
    "explotable primero, CADA una en UNA frase: hallazgo concreto + cómo "
    "abusarlo + qué consigues. Ej: '- SMB (445) permite sesión nula con "
    "ESCRITURA en el share public: sube un webshell o roba archivos.' Si de "
    "verdad no hay nada atacable, dilo en una línea.\n"
    "## Siguientes pasos\n"
    "Comandos concretos y LISTOS PARA PEGAR Y EJECUTAR (en bloques de código), "
    "uno por línea con un comentario de qué busca, DERIVADOS de los hallazgos de "
    "arriba (no genéricos). Usa herramientas reales: nmap, searchsploit, hydra, "
    "ffuf, netexec, smbclient, snmpwalk, curl, wpscan, etc.\n"
    "Reglas estrictas (incumplirlas arruina el análisis):\n"
    "- NADA de marcadores tipo <IP>, <usuario> o <diccionario>. Rellena SIEMPRE "
    "con valores reales: la IP/dominio exactos (te los doy abajo), rutas reales "
    "de wordlists (/usr/share/wordlists/rockyou.txt, /usr/share/seclists/...), "
    "usuarios reales del informe si los hay. El comando debe ejecutarse tal cual.\n"
    "- PROHIBIDO inventar: no te saques CVE concretos, ni nombres de módulos de "
    "metasploit, ni exploits que no sepas que existen de verdad. Para encontrar "
    "exploits manda SIEMPRE a 'searchsploit <producto> <version>', nunca cites un "
    "módulo msf de memoria.\n"
    "- No inventes puertos ni servicios que no aparezcan en el informe.\n"
    "- Mejor decir 'hay que comprobarlo con X' que inventar un dato falso."
)

_SYSTEM_NET = (
    "Eres un pentester ofensivo ayudando en un test autorizado y en el estudio "
    "del eJPT. Te paso el MAPA DE RED que ha generado tarascan: una tabla de "
    "equipos vivos de una subred con su IP, hostname, SO, puertos, MAC y "
    "fabricante. Piensa como un atacante que acaba de entrar en la red y decide "
    "por dónde empezar. No des consejos de defensa ni hardening. Responde en "
    "español, conciso, con estas tres secciones y en este orden:\n"
    "## Resumen\n"
    "Cómo es la red en 3-5 frases: cuántos equipos, qué tipos hay (servidores, "
    "NAS, routers, Windows, Linux...) y qué pinta general tiene.\n"
    "## Objetivos prioritarios\n"
    "Lista de viñetas ordenada del más jugoso al menos. CADA viñeta en UNA frase: "
    "IP del equipo, por qué es interesante (servicio/SO/rol) y qué atacarías "
    "primero. Ej: '- 192.168.1.20 (Windows, SMB 445): intento de null session y "
    "fuerza bruta con netexec para sacar usuarios y un posible acceso.'\n"
    "## Siguientes pasos\n"
    "Comandos concretos y LISTOS PARA PEGAR Y EJECUTAR (en bloques de código) "
    "para profundizar en los equipos prioritarios, uno por línea con un "
    "comentario de qué busca. Usa las IP reales de la tabla, nada de marcadores.\n"
    "Reglas estrictas:\n"
    "- No inventes equipos, IP ni puertos que no estén en la tabla.\n"
    "- No cites CVE concretos salvo que estés seguro; si no, manda verificar.\n"
    "- Mejor decir 'hay que comprobarlo' que inventar un dato falso."
)


class AIError(RuntimeError):
    """Error controlado de la fase de IA (clave ausente, fallo de red, etc.).

    retriable=True indica que tiene sentido probar con otro modelo de la cadena
    (saturación, modelo no disponible, timeout...); False es fatal (p.ej. clave).
    """

    def __init__(self, message: str, retriable: bool = False):
        super().__init__(message)
        self.retriable = retriable


def _candidate_models() -> list[str]:
    """Modelos a probar en orden. Si el usuario fija uno, va primero."""
    override = os.environ.get("TARASCAN_AI_MODEL", "").strip()
    if override:
        return [override] + [m for m in _FALLBACK_MODELS if m != override]
    return list(_FALLBACK_MODELS)


def get_key() -> str | None:
    """Devuelve la clave de API de la primera variable de entorno definida."""
    for var in _KEY_VARS:
        value = os.environ.get(var)
        if value and value.strip():
            return value.strip()
    return None


def _request(model: str, system: str, user_msg: str, key: str, base: str, timeout: int) -> str:
    """Hace la petición a UN modelo y devuelve su respuesta limpia.

    Reintenta ante 503/429 (saturación). Lanza AIError(retriable=True) cuando
    tiene sentido pasar al siguiente modelo de la cadena.
    """
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.2,
        "max_tokens": 4000,
    }
    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    data = None
    for intento in range(_MAX_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8")[:200]
            except Exception:  # noqa: BLE001
                pass
            if exc.code in (401, 403):  # clave mala: fatal, no sirve cambiar de modelo
                raise AIError(f"la API rechazó la clave ({exc.code}): revisa TARASCAN_AI_KEY.") from exc
            if exc.code == 404:
                raise AIError(f"'{model}' no disponible (404)", retriable=True) from exc
            if exc.code in (429, 503):
                if intento < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_WAIT * (intento + 1))
                    continue
                raise AIError(f"'{model}' saturado ({exc.code})", retriable=True) from exc
            raise AIError(f"'{model}' devolvió error {exc.code}: {detail}", retriable=True) from exc
        except urllib.error.URLError as exc:
            raise AIError(f"no se pudo conectar con la API: {exc.reason}") from exc
        except TimeoutError as exc:
            raise AIError(f"'{model}' tardó demasiado (timeout)", retriable=True) from exc

    if data is None:
        raise AIError(f"'{model}' no dio respuesta", retriable=True)

    try:
        content = data["choices"][0]["message"].get("content") or ""
    except (KeyError, IndexError, TypeError) as exc:
        raise AIError(f"'{model}': respuesta inesperada", retriable=True) from exc

    # Modelos de razonamiento: quitamos los <think>...</think> si los metieran en content.
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
    if not content:  # se quedó razonando sin escribir la respuesta: probar otro
        raise AIError(f"'{model}' no devolvió texto (solo razonamiento)", retriable=True)
    return content


def analyze(report_md: str, target: str | None = None, kind: str = "target") -> tuple[str, str]:
    """Analiza el informe recorriendo la cadena de modelos de respaldo.

    kind="target" analiza el recon de un objetivo; kind="net" analiza un mapa de red.
    Devuelve (texto_en_markdown, modelo_que_respondió).
    """
    key = get_key()
    if not key:
        raise AIError(
            "no hay clave de API: define TARASCAN_AI_KEY con una clave gratuita "
            "de build.nvidia.com (o NVIDIA_API_KEY). Mira el README."
        )

    base = os.environ.get("TARASCAN_AI_BASE", DEFAULT_BASE).rstrip("/")
    try:
        timeout = int(os.environ.get("TARASCAN_AI_TIMEOUT", "300"))
    except ValueError:
        timeout = 300

    report = report_md.strip()
    if len(report) > _MAX_CHARS:
        report = report[:_MAX_CHARS] + "\n\n[informe recortado por longitud]"

    system = _SYSTEM_NET if kind == "net" else _SYSTEM
    etiqueta = "Subred escaneada" if kind == "net" else "Objetivo exacto (úsalo literal en los comandos)"
    objetivo = f"{etiqueta}: {target}\n\n" if target else ""
    user_msg = objetivo + "Informe de tarascan:\n\n" + report

    errores = []
    for model in _candidate_models():
        try:
            return _request(model, system, user_msg, key, base, timeout), model
        except AIError as exc:
            if not exc.retriable:
                raise
            errores.append(str(exc))
            continue

    raise AIError(
        "ningún modelo respondió (todos saturados o no disponibles). Prueba en "
        "un rato. Detalle: " + "; ".join(errores)
    )

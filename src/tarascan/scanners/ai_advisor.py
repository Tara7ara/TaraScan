"""Análisis con IA del informe (opt-in, --ai). Endpoint OpenAI-compatible (NVIDIA free por defecto); la clave va en una variable de entorno, nunca en el repo."""

import json
import os
import re
import time
import urllib.error
import urllib.request

# Endpoint y modelo por defecto (cambiables por variable de entorno).
DEFAULT_BASE = "https://integrate.api.nvidia.com/v1"
DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"

# Cadena de respaldo: de más potente a más seguro. TARASCAN_AI_MODEL va primero si se define.
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

# Caja de herramientas de tarascan: para que la IA proponga flags propias, no bash suelto.
_TOOLBOX = (
    "CAJA DE HERRAMIENTAS DE TARASCAN (conócela: para los siguientes pasos, si "
    "una flag de tarascan cubre la acción, propón la flag en vez del comando de "
    "bash suelto). Invocación: 'tarascan <objetivo> [flags]'.\n"
    "Ya ejecutado en el recon base (NO lo repropongas como si fuera nuevo, salvo "
    "para afinar algo concreto): nmap top-100 + versiones, searchsploit de los "
    "servicios, banners con nc, NSE; en web: whatweb, wafw00f, cabeceras HTTP, "
    "vhost, gobuster, ffuf, nikto, nuclei, y wpscan si detectó WordPress; en SMB "
    "(139/445): smbclient, enum4linux, nbtscan, netexec; sslscan en 443/8443; "
    "snmp y onesixtyone; en dominios: dns, transferencia de zona, subfinder.\n"
    "Flags que SÍ lanzan trabajo nuevo (úsalas en los siguientes pasos cuando el "
    "hallazgo lo justifique):\n"
    "- tarascan <objetivo> --full -> nmap a los 65535 puertos (si sospechas "
    "servicios fuera del top-100).\n"
    "- tarascan <objetivo> --deep -> feroxbuster recursivo (si gobuster/ffuf "
    "dejaron directorios jugosos a medio explorar).\n"
    "- tarascan <objetivo> --sqli -> sqlmap contra la web detectada (si hay "
    "parámetros o formularios candidatos a inyección).\n"
    "- tarascan <objetivo> --brute <servicio> -> hydra (ssh, ftp, http-get, "
    "http-post-form...), solo si hay un login real que atacar.\n"
    "- tarascan <objetivo> --only LISTA / --skip LISTA -> reenfocar el recon en "
    "pocas herramientas (p.ej. --only nuclei,smbclient).\n"
    "- tarascan --net <CIDR> -> mapa de la red local (si el objetivo sugiere "
    "pivotar a otros equipos).\n"
    "Para TODO lo que tarascan NO envuelve (explotar un share con smbclient a "
    "mano, pegarle a un endpoint con curl, searchsploit de un producto concreto, "
    "crackear un hash, msfconsole, etc.) usa el comando de bash real de siempre."
)

# Catálogo de subcomandos: para que el copiloto conozca toda la herramienta, no solo las flags.
_SUBCOMMANDS = (
    "SUBCOMANDOS de tarascan (fórmula: 'tarascan <subcomando> ...'). Proponlos "
    "como siguiente paso cuando encajen con los hallazgos, igual de válidos que "
    "las flags de recon:\n"
    "- tarascan audit <ssh|tls|smb> <IP> -> auditoría de config débil del servicio "
    "(algoritmos SSH, TLS deprecado, null session/SMB signing). Úsalo si hay 22, "
    "443/TLS o 139/445.\n"
    "- tarascan web <url> -> descubre swagger/openapi/graphql y audita CORS de una "
    "web concreta (si hay un servicio http/https).\n"
    "- tarascan cve <producto> <version> -> exploits conocidos en exploit-db "
    "(cuando el recon dio un banner con producto+versión, p.ej. 'vsftpd 2.3.4').\n"
    "- tarascan osint <dominio> -> OSINT pasivo (crt.sh, SPF/DMARC/DKIM, cabeceras). "
    "SOLO para dominios, nunca para una IP.\n"
    "- tarascan report <IP> -> informe consolidado de todo lo que se ha escaneado "
    "del objetivo (cierre de la fase).\n"
    "Utilidades de análisis (MUY IMPORTANTE: úsalas SIEMPRE que en el informe o en "
    "la salida de un comando aparezca su entrada, rellenando el valor EXACTO que "
    "ves, para extraer toda la información):\n"
    "- si ves un HASH (p.ej. un MD5/NTLM de 32 hex, un $6$..., un $krb5tgs$..., un "
    "LM:NT): propón 'tarascan hash <el hash literal>' para identificar el tipo y el "
    "modo de Hashcat/John.\n"
    "- si ves una cadena CODIFICADA (Base64, hex, URL-encode...): propón 'tarascan "
    "decode <la cadena>' para decodificarla en cascada.\n"
    "- si ves un JWT (xxx.yyy.zzz): propón 'tarascan jwt <el token>' para "
    "desglosarlo y ver si es forjable.\n"
    "- si ves un binario con SUID, con capabilities o permitido por sudo (p.ej. "
    "en la salida de 'sudo -l', find/vim/awk/env/python...): propón 'tarascan "
    "gtfobins <binario>' para el one-liner exacto de escalada a root.\n"
    "- utilidades manuales (solo si vienen a cuento): tarascan shell, tarascan "
    "serve, tarascan pivot.\n"
    "Regla: no inventes subcomandos ni opciones; usa SOLO los de esta lista, y "
    "cuando uses hash/decode/jwt copia el valor TAL CUAL aparece."
)

_SYSTEM = (
    "Eres un analista de seguridad ofensiva en una prueba de penetración "
    "autorizada y para el estudio del eJPT. Te paso el informe de recon de la "
    "herramienta tarascan sobre un objetivo con permiso explícito del propietario. "
    "Céntrate en la evaluación ofensiva: identifica la superficie de ataque y los "
    "vectores de acceso priorizados a partir de los hallazgos concretos. No hace "
    "falta que incluyas apartados de mitigación ni hardening. Responde en español, "
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
    "arriba (no genéricos).\n"
    "PRIORIDAD de los comandos (muy importante): si una flag de la caja de "
    "herramientas de tarascan cubre el siguiente paso, PROPÓN LA FLAG DE TARASCAN, "
    "no el comando de bash equivalente. Ejemplos de cómo mapear un hallazgo a su "
    "flag: login SSH/FTP que atacar -> 'tarascan <objetivo> --brute ssh'; "
    "parámetro o formulario inyectable -> 'tarascan <objetivo> --sqli'; muchos "
    "directorios a medio explorar -> 'tarascan <objetivo> --deep'; sospecha de "
    "servicios fuera del top-100 -> 'tarascan <objetivo> --full'. Solo cuando "
    "tarascan NO tenga una flag para esa acción (explotar un share concreto, "
    "pegarle a un endpoint con curl, searchsploit de un producto, crackear un "
    "hash, msfconsole...) usa el comando de bash real: nmap, searchsploit, hydra, "
    "ffuf, netexec, smbclient, snmpwalk, curl, wpscan, etc.\n"
    "Reglas estrictas (incumplirlas arruina el análisis):\n"
    "- NADA de marcadores tipo <IP>, <usuario> o <diccionario>. Rellena SIEMPRE "
    "con valores reales: la IP/dominio exactos (te los doy abajo; úsalos también "
    "en los comandos 'tarascan ...'), rutas reales de wordlists "
    "(/usr/share/wordlists/rockyou.txt, /usr/share/seclists/...), usuarios reales "
    "del informe si los hay. El comando debe ejecutarse tal cual.\n"
    "- No repropongas una herramienta que el recon base YA lanzó (nuclei, wpscan, "
    "smbclient, enum4linux, gobuster...) como si fuera un paso nuevo; solo si vas "
    "a afinarla con un argumento concreto que el recon no usó.\n"
    "- PROHIBIDO inventar: no te saques CVE concretos, ni nombres de módulos de "
    "metasploit, ni exploits que no sepas que existen de verdad. Para encontrar "
    "exploits manda SIEMPRE a 'searchsploit <producto> <version>', nunca cites un "
    "módulo msf de memoria.\n"
    "- No inventes puertos ni servicios que no aparezcan en el informe.\n"
    "- No te inventes flags de tarascan: usa SOLO las de la caja de herramientas.\n"
    "- Mejor decir 'hay que comprobarlo con X' que inventar un dato falso.\n\n"
    + _TOOLBOX
)

_SYSTEM_NET = (
    "Eres un pentester ofensivo ayudando en un test autorizado y en el estudio "
    "del eJPT. Te paso el MAPA DE RED que ha generado tarascan: una tabla de "
    "equipos vivos de una subred con su IP, hostname, SO, puertos, MAC y "
    "fabricante. Evalúa la red desde la perspectiva ofensiva y decide por dónde "
    "empezar según el valor de cada equipo. No hace falta que incluyas apartados "
    "de defensa ni hardening. Responde en "
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
    "PRIORIDAD: el siguiente paso natural desde un mapa de red es lanzar el recon "
    "completo de tarascan sobre cada equipo jugoso: propón 'tarascan <IP>' (y sus "
    "flags cuando toque, p.ej. '--brute ssh' si hay SSH, '--sqli' si hay web con "
    "parámetros) ANTES que un comando de bash suelto. Deja el bash solo para lo "
    "que tarascan no envuelve.\n"
    "Reglas estrictas:\n"
    "- No inventes equipos, IP ni puertos que no estén en la tabla.\n"
    "- No te inventes flags de tarascan: usa SOLO las de la caja de herramientas.\n"
    "- No cites CVE concretos salvo que estés seguro; si no, manda verificar.\n"
    "- Mejor decir 'hay que comprobarlo' que inventar un dato falso.\n\n"
    + _TOOLBOX
)


# Modo guiado: el modelo responde JSON estructurado, no prosa,
# mapeando los hallazgos a FLAGS REALES de tarascan para un menú interactivo.
_SYSTEM_GUIDED = (
    "Eres el copiloto ofensivo de tarascan en un test autorizado. Conoces TODA la "
    "herramienta (flags de recon Y subcomandos). Te paso el informe de recon de un "
    "objetivo; analízalo y propón los siguientes pasos EXCLUSIVAMENTE como comandos "
    "de tarascan, eligiendo en cada caso la pieza de tarascan que mejor aproveche "
    "el hallazgo (una flag de recon, o un subcomando como audit/web/cve/report).\n"
    "Responde SOLO con un objeto JSON válido, sin texto antes ni después, sin "
    "bloques de código, con este esquema exacto:\n"
    '{"resumen": "<2-4 frases sobre la superficie de ataque>", '
    '"acciones": [{"comando": "tarascan ...", "motivo": "<una frase: qué hallazgo '
    'lo justifica y qué consigues>"}]}\n'
    "Cada comando es UNA de estas dos formas, nada más:\n"
    "  a) recon del mismo objetivo con flag: 'tarascan <objetivo> <--full|--deep|"
    "--sqli|--brute <servicio>|--only <lista>|--skip <lista>>'.\n"
    "  b) un subcomando: 'tarascan audit <ssh|tls|smb> <objetivo>', 'tarascan web "
    "<url>', 'tarascan cve <producto> <version>', 'tarascan report <objetivo>', y "
    "las utilidades (hash/decode/jwt/shell/serve/pivot) solo si vienen a cuento.\n"
    "Reglas:\n"
    "- El <objetivo> es el que te doy abajo, literal (la IP/dominio). Para 'web' "
    "monta la URL con su esquema y puerto reales del informe.\n"
    "- 'osint' solo si el objetivo es un dominio, nunca una IP.\n"
    "- No inventes flags, subcomandos ni opciones: usa SOLO los del catálogo.\n"
    "- Variedad: si hay SMB audita SMB, si hay web mira la web, etc.; no repitas "
    "seis veces lo mismo.\n"
    "- Si en los resultados aparece un hash, una cadena codificada o un JWT, "
    "analízalo con 'tarascan hash/decode/jwt <valor exacto>' (ver utilidades abajo).\n"
    "- Si no hay nada accionable, devuelve \"acciones\": [].\n"
    "- Máximo 6 acciones, la más jugosa primero.\n\n"
    + _TOOLBOX + "\n\n" + _SUBCOMMANDS
)


# Modo guiado desde un MAPA DE RED: aquí el siguiente paso no es una flag, es
# escanear con tarascan los equipos más jugosos de la tabla.
_SYSTEM_GUIDED_NET = (
    "Eres el copiloto ofensivo de tarascan en un test autorizado. Te paso el MAPA "
    "DE RED (tabla de equipos vivos con IP, hostname, SO, puertos, MAC y "
    "fabricante). Decide por qué equipos empezar y proponlos como comandos de "
    "tarascan.\n"
    "Responde SOLO con un objeto JSON válido, sin texto ni bloques de código, con "
    "este esquema exacto:\n"
    '{"resumen": "<2-4 frases sobre la red>", "acciones": [{"comando": "tarascan '
    '...", "motivo": "<una frase: por qué ese equipo es jugoso y qué esperas>"}]}\n'
    "Cada comando apunta a una IP EXACTA de la tabla y es UNA de estas formas:\n"
    "  a) recon del equipo: 'tarascan <IP>' (puedes añadir '--full' si solo tiene "
    "puertos raros).\n"
    "  b) un subcomando dirigido: 'tarascan audit <ssh|tls|smb> <IP>' según los "
    "puertos de ese equipo (22->ssh, 443->tls, 139/445->smb), o 'tarascan web "
    "http://<IP>' si sirve web.\n"
    "Reglas:\n"
    "- Ordena de más jugoso a menos (servidores, NAS, equipos con SMB/varios "
    "servicios antes que una impresora o una cámara).\n"
    "- No inventes IPs que no estén en la tabla. Máximo 6 acciones.\n"
    "- NADA intrusivo (--sqli/--brute): es un barrido inicial de red."
)


class AIError(RuntimeError):
    """Error de la fase de IA; retriable=True si vale la pena probar otro modelo de la cadena."""

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
    """Petición a UN modelo; reintenta ante 503/429 y lanza AIError(retriable) para pasar al siguiente."""
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
    """Analiza el informe por la cadena de modelos. kind target|net. Devuelve (markdown, modelo)."""
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


_REFUSAL_HINTS = (
    "i cannot", "i can't", "i'm sorry", "no puedo ayudar", "no puedo asistir",
    "cannot assist", "i am not able", "va en contra", "unethical", "i won't",
)


def _looks_like_refusal(text: str) -> bool:
    """Heurística: el modelo soltó un rechazo ético en vez de la respuesta pedida."""
    low = text.lower()
    return any(h in low for h in _REFUSAL_HINTS)


def _extract_json(text: str) -> dict:
    """Saca el objeto JSON de la respuesta, tolerando ```json ...``` o texto alrededor."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    else:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            text = text[start:end + 1]
    return json.loads(text)


def suggest_actions(report_md: str, target: str, kind: str = "target",
                    already_run: list[str] | None = None) -> tuple[str, list[dict], str]:
    """Modo guiado: devuelve (resumen, acciones, modelo); cada acción es {comando, motivo}.
    kind target|net. already_run son comandos ya lanzados, para no reproponerlos.
    La validación la hace cli."""
    key = get_key()
    if not key:
        raise AIError(
            "no hay clave de API: define TARASCAN_AI_KEY con una clave gratuita "
            "de build.nvidia.com (o NVIDIA_API_KEY). Mira el README."
        )

    base = os.environ.get("TARASCAN_AI_BASE", DEFAULT_BASE).rstrip("/")
    # Modo guiado interactivo: timeout corto (60s) para no colgarse si el endpoint va lento.
    try:
        timeout = int(os.environ.get(
            "TARASCAN_AI_GUIDED_TIMEOUT",
            os.environ.get("TARASCAN_AI_TIMEOUT", "60"),
        ))
    except ValueError:
        timeout = 60

    report = report_md.strip()
    if len(report) > _MAX_CHARS:
        report = report[:_MAX_CHARS] + "\n\n[informe recortado por longitud]"
    hechos = ""
    if already_run:
        lista = "\n".join(f"- {c}" for c in already_run)
        hechos = ("\nYA EJECUTADO en esta sesión (NO lo vuelvas a proponer, ni una "
                  "variante trivial como cambiar http/https o la barra final):\n"
                  f"{lista}\n")
    if kind == "net":
        system = _SYSTEM_GUIDED_NET
        user_msg = f"Subred escaneada: {target}\n{hechos}\nMapa de red de tarascan:\n\n" + report
    else:
        system = _SYSTEM_GUIDED
        user_msg = (
            f"Objetivo exacto (úsalo literal en cada comando): {target}\n{hechos}\n"
            "Informe de tarascan:\n\n" + report
        )

    errores = []
    for model in _candidate_models():
        try:
            raw = _request(model, system, user_msg, key, base, timeout)
        except AIError as exc:
            if not exc.retriable:
                raise
            errores.append(str(exc))
            continue
        try:
            data = _extract_json(raw)
        except ValueError:
            if _looks_like_refusal(raw):
                errores.append(f"'{model}' respondió con un rechazo de seguridad en vez de JSON "
                               "(prueba otro modelo con TARASCAN_AI_MODEL)")
            else:
                errores.append(f"'{model}' no devolvió JSON válido")
            continue
        acciones = data.get("acciones") or []
        if not isinstance(acciones, list):
            acciones = []
        acciones = [a for a in acciones if isinstance(a, dict) and a.get("comando")]
        return str(data.get("resumen", "")).strip(), acciones, model

    raise AIError(
        "el copiloto no obtuvo respuesta utilizable. Detalle: " + "; ".join(errores)
    )

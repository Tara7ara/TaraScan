#!/bin/sh
# Abre un listener TCP por cada argumento recibido. Dos formatos:
#   PORT          -> solo abre el puerto (la conexion se acepta y se cierra).
#   PORT=BANNER    -> al conectarse, envia BANNER + CRLF (p.ej. banner SSH/HTTP).
#
# Ejemplo:  sim.sh 23 "22=SSH-2.0-OpenSSH_9.2p1 Raspbian-2"
#
# Pensado solo para el laboratorio local de TaraScan: ningun puerto hace nada
# util, solo responden lo justo para que el mapa de red los vea.

if [ "$#" -eq 0 ]; then
    echo "uso: sim.sh PUERTO[=BANNER] [PUERTO[=BANNER] ...]" >&2
    exit 1
fi

for spec in "$@"; do
    port=${spec%%=*}
    banner=${spec#*=}

    if [ "$banner" = "$spec" ]; then
        # Sin banner: aceptar la conexion y cerrar.
        socat TCP-LISTEN:"$port",fork,reuseaddr /dev/null &
    else
        # Con banner: enviarlo al conectarse y mantener la conexion un momento.
        # El banner va por entorno: socat 1.8 se come las comillas de SYSTEM:.
        BANNER="$banner" socat TCP-LISTEN:"$port",fork,reuseaddr \
            EXEC:/usr/local/bin/banner.sh &
    fi
done

echo "simdevice escuchando en: $*"
wait

# Dispositivo de red "de pega" para el laboratorio de TaraScan.
#
# No es un servicio real: solo abre los puertos TCP que le digas y, opcionalmente,
# suelta un banner al conectarse. Sirve para poblar la subred del lab con hosts
# variados (router, NAS, Raspberry Pi...) y que el mapa de red (`tarascan --net`)
# tenga algo que descubrir: IP viva, puertos abiertos, banner y, con la MAC que
# le pongas en docker-compose, fabricante vía OUI y SO deducido.
FROM alpine:3.20

RUN apk add --no-cache socat

COPY sim.sh banner.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/sim.sh /usr/local/bin/banner.sh

ENTRYPOINT ["/usr/local/bin/sim.sh"]

# FTP del laboratorio: vsftpd real con banner "2.3.4" y credenciales débiles.
# Sirve para probar `--brute ftp` (hydra encuentra admin:123456) y `cve`/searchsploit
# en vivo (nmap lee el banner y lo identifica como vsftpd 2.3.4, con exploits conocidos).
# Credenciales de MENTIRA, solo para el lab.
FROM alpine:3.20

RUN apk add --no-cache vsftpd && \
    adduser -D -h /home/admin admin && \
    echo "admin:123456" | chpasswd

COPY vsftpd.conf /etc/vsftpd/vsftpd.conf

EXPOSE 21 21000-21010
CMD ["vsftpd", "/etc/vsftpd/vsftpd.conf"]

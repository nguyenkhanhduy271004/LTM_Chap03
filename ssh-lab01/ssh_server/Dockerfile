FROM alpine:latest

RUN apk add --no-cache openssh-server

RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

RUN adduser -h /home/seed -s /bin/sh -D seed

RUN echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config

RUN echo 'seed:dees' | chpasswd

COPY entrypoint.sh /

RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]

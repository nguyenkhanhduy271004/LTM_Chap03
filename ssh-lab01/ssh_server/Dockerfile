# ssh_server/Dockerfile
FROM alpine:latest


RUN apk add --no-cache openssh-server 
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

RUN adduser -h /home/seed -s /bin/sh -D seed
RUN echo -n 'seed:dees' | chpasswd
ENTRYPOINT [ "./entrypoint.sh" ]

EXPOSE 22
COPY entrypoint.sh /

RUN chmod +x -v entrypoint.sh
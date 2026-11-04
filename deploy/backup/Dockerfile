FROM alpine:3.20
RUN apk add --no-cache postgresql16-client age rclone bash tar coreutils tzdata
COPY backup.sh restore.sh entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh && adduser -D -u 10001 backup
USER backup
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

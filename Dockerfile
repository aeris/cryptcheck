FROM alpine:edge

COPY --chown=1000:1000 . /home/cryptcheck
RUN apk add --update bash && bash /home/cryptcheck/docker/build.sh

ENTRYPOINT [ "su-exec", "cryptcheck", "bash", "/home/cryptcheck/docker/entrypoint.sh" ]
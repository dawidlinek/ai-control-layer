# wcss-link: SSH forward from the compose network to vLLM on WCSS (see README.md).
FROM alpine:3.22

RUN apk add --no-cache openssh-client curl tini \
    && adduser -D -u 10001 -s /sbin/nologin wcss

COPY wcss-link.sh /usr/local/bin/wcss-link
# normalise line endings (Windows checkouts) and make the script executable
RUN sed -i 's/\r$//' /usr/local/bin/wcss-link && chmod 0755 /usr/local/bin/wcss-link

USER 10001:10001
WORKDIR /home/wcss
ENV LISTEN_PORT=8001
EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=3 \
    CMD curl -fsS -o /dev/null -m 10 "http://127.0.0.1:${LISTEN_PORT}/health" || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/bin/wcss-link"]

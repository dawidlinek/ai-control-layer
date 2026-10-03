FROM python:3.12-slim-bookworm
RUN useradd --system --uid 10002 feed \
 && mkdir -p /srv/state \
 && chown feed /srv/state
WORKDIR /srv
COPY server.py ed25519.py ./
COPY bundles ./bundles
ENV STATE_DIR=/srv/state
USER feed
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2).status==200 else 1)"
CMD ["python", "server.py"]

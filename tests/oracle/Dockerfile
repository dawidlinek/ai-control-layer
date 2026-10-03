# Attacker sink for exfiltration tests: records every request it receives, `GET /_log` returns them.
# Build context: tests/oracle   (docker build -t acl-attacker-sink tests/oracle)
FROM python:3.12-slim
WORKDIR /app
COPY sink.py /app/sink.py
ENV PORT=8080 PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8080'))"
CMD ["python", "/app/sink.py"]

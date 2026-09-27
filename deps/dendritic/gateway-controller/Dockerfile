FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 gateway \
 && useradd --uid 10001 --gid gateway --home-dir /app --no-create-home gateway
WORKDIR /app
COPY requirements.txt .
RUN pip install --requirement requirements.txt
COPY backend ./backend
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini
COPY config.example.yaml ./config.yaml
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"
CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers"]

# ── Build stage ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="APIGuard Enterprise"
LABEL org.opencontainers.image.description="REST API Security Scanner — OWASP API Top 10"
LABEL org.opencontainers.image.version="4.0.0"
LABEL org.opencontainers.image.vendor="APIGuard Security"

# Non-root user for security
RUN groupadd -r apiguard && useradd -r -g apiguard apiguard

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY --chown=apiguard:apiguard . .

# Data directory for SQLite (fallback) or logs
RUN mkdir -p /data && chown apiguard:apiguard /data

USER apiguard

# Environment
ENV APIGUARD_ENV=production
ENV APIGUARD_DEBUG=false
ENV APIGUARD_DB=/data/apiguard_history.db
ENV APIGUARD_AUTH_DB=/data/apiguard_auth.db
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
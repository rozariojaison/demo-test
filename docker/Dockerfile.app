FROM python:3.12-slim

# Non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Dependency layer — cached separately from app code
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY app/ ./app/
COPY middleware/ ./middleware/
COPY migrations/ ./migrations/
COPY migrations/alembic.ini ./alembic.ini

# Secrets directory — mounted at runtime, never baked into image
RUN mkdir -p secrets && chown appuser:appuser secrets

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--loop", "uvloop", "--http", "httptools"]

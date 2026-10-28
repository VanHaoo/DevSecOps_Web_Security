# ---------- Build stage ----------
FROM python:3.12-slim AS base

# Security: run as non-root
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Install dependencies first (Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ app/
COPY wsgi.py .
COPY scripts/ scripts/

# Create instance directory for SQLite
RUN mkdir -p instance && chown -R appuser:appuser /app

USER appuser

# Environment variables
ENV FLASK_ENV=production
ENV SECRET_KEY=change-this-in-production

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Run with Gunicorn (production server)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "wsgi:app"]

# Production Dockerfile for FastAPI ML Backend
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code, dataset, and artifacts
COPY app/ ./app/
COPY artifacts/ ./artifacts/
COPY data/ ./data/
COPY reports/ ./reports/

# Create non-privileged service user
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/data /app/artifacts && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Health check against API endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

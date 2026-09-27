# ==============================================================================
# CyberWorld Backend — Production Dockerfile
# Multi-stage lightweight Python container with CPU-optimized PyTorch
# ==============================================================================

FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    CYBERWORLD_ENV=production \
    PORT=8000

WORKDIR /app

# Install minimal OS dependencies for network health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install PyTorch CPU-only wheel first to avoid pulling heavy ~2.5GB CUDA packages
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Copy and install python dependencies
COPY cyberworld/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy backend source code and model artifacts
COPY cyberworld/ /app/cyberworld/
COPY artifacts/ /app/artifacts/

# Ensure artifacts directory has write permissions for SQLite database and logs
RUN mkdir -p /app/artifacts && chmod -R 777 /app/artifacts

EXPOSE 8000

# Built-in Docker health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Production ASGI server execution
CMD ["uvicorn", "cyberworld.backend.api:app", "--host", "0.0.0.0", "--port", "8000"]

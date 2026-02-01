# =============================================================================
# Universal Polyglot API Scanner v4.0 - Production Dockerfile
# =============================================================================
# Multi-stage build for optimized image size
#
# Build:
#   docker build -t api-scanner:latest .
#
# Run (Basic):
#   docker run -v $(pwd):/code -v $(pwd)/output:/output api-scanner:latest
#
# Run (Parallel + SARIF):
#   docker run -v $(pwd):/code -v $(pwd)/output:/output \
#     -e SCANNER_PARALLEL=true \
#     -e SCANNER_WORKERS=8 \
#     api-scanner:latest --export-sarif /output/scan.sarif
#
# Run with Invicti Sync:
#   docker run -v $(pwd):/code \
#     -e INVICTI_SYNC=true \
#     -e INVICTI_URL=https://www.netsparkercloud.com \
#     -e INVICTI_USER=your-user-id \
#     -e INVICTI_TOKEN=your-token \
#     -e INVICTI_WEBSITE_ID=your-website-id \
#     api-scanner:latest
#
# Author: Principal Security Engineer
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder - Install dependencies
# -----------------------------------------------------------------------------
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: Production - Minimal runtime image
# -----------------------------------------------------------------------------
FROM python:3.11-slim as production

# Labels for container metadata
LABEL maintainer="Principal Security Engineer" \
      description="Universal Polyglot API Scanner v4.0 - Production Ready" \
      version="4.0.0" \
      org.opencontainers.image.source="https://github.com/yourorg/api-scanner" \
      org.opencontainers.image.title="Universal Polyglot API Scanner" \
      org.opencontainers.image.description="Enterprise-grade API discovery with parallel processing, policy engine, SARIF/JUnit output"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    bash \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create app directory
WORKDIR /app

# Copy application files
COPY main.py /app/main.py
COPY invicti_sync.py /app/invicti_sync.py
COPY entrypoint.sh /app/entrypoint.sh

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Create output directory
RUN mkdir -p /output && chmod 777 /output

# Create non-root user for security
RUN useradd -m -s /bin/bash scanner && \
    chown -R scanner:scanner /app /output
USER scanner

# Environment variables with defaults
ENV TARGET_DIR=/code \
    OUTPUT_DIR=/output \
    OPENAPI_FILE=/output/openapi.json \
    INVICTI_SYNC=false \
    DRY_RUN=false \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Scanner v4.0 configuration
    SCANNER_PARALLEL=false \
    SCANNER_WORKERS=4 \
    SCANNER_MAX_FILE_SIZE=10 \
    SCANNER_INCREMENTAL=false \
    SCANNER_FAIL_ON_CRITICAL=false \
    SCANNER_METRICS=false

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Volumes
VOLUME ["/code", "/output"]

# Entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command (can be overridden)
CMD []

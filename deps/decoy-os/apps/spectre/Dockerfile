# Multi-arch Dockerfile for Spectre HIDS
# Build: docker buildx build --platform linux/amd64,linux/arm64 -t spectre/hids:latest --push .
# Run: docker run -d --privileged --pid=host --cgroupns=host -v /:/host:ro spectre/hids:latest

# =============================================================================
# BUILD STAGE
# =============================================================================
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cargo \
    rustc \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create build user and directory
RUN useradd -m -u 1000 builder && mkdir /build && chown builder:builder /build
WORKDIR /build
USER builder

# Copy project files
COPY --chown=builder:builder pyproject.toml README.md ./
COPY --chown=builder:builder spectre/ spectre/
COPY --chown=builder:builder cli/ cli/
COPY --chown=builder:builder rules.json ./

# Install in editable mode for development, or build wheel
RUN pip install --user --no-cache-dir ".[yara]"

# =============================================================================
# RUNTIME STAGE - Distroless for minimal attack surface
# =============================================================================
FROM gcr.io/distroless/python3-debian12:nonroot

# Copy Python packages from builder
COPY --from=builder /home/builder/.local /home/nonroot/.local

# Copy application code
COPY --from=builder /build/spectre /app/spectre
COPY --from=builder /build/cli /app/cli
COPY --from=builder /build/rules.json /app/rules.json

# Set Python path
ENV PYTHONPATH=/app:/home/nonroot/.local/lib/python3.11/site-packages
ENV PATH=/home/nonroot/.local/bin:$PATH

# Runtime configuration
ENV SPECTRE_INTERVAL=0.5
ENV SPECTRE_WINDOW_SIZE=60.0
ENV SPECTRE_THRESHOLD=15
ENV SPECTRE_LOG_FILE=/var/log/spectre/alerts.log
ENV SPECTRE_DB_PATH=/var/lib/spectre/spectre.db
ENV SPECTRE_YARA_RULES=/app/spectre/yara_rules
ENV SPECTRE_CONTAIN=none
ENV SPECTRE_API=false
ENV SPECTRE_API_PORT=8000
ENV SPECTRE_VERBOSE=false

# Create directories for logs and data (will be mounted at runtime)
# Distroless doesn't have mkdir, so we rely on volume mounts

WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.path.insert(0, '/app'); from spectre.storage import SpectreDB; db = SpectreDB('/var/lib/spectre/spectre.db'); print(db.get_stats()); db.close()" || exit 1

# Default command
ENTRYPOINT ["python", "-m", "cli.main"]
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="Spectre HIDS"
LABEL org.opencontainers.image.description="Behavioral Host Intrusion Detection System with Active Containment"
LABEL org.opencontainers.image.version="10.0.0"
LABEL org.opencontainers.image.authors="Aayush Bankar <aayushbankar42@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/Aayushbankar/spectre"
LABEL org.opencontainers.image.documentation="https://github.com/Aayushbankar/spectre/tree/main/docs"
LABEL org.opencontainers.image.licenses="MIT"
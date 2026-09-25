FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ORIN_DB_PATH=/var/lib/orin/orin_vault.db

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY rules/ ./rules/
COPY assets/ ./assets/

# Install the package with hub server dependencies
RUN pip install --no-cache-dir .[hub]

# Create non-root user and persistent directories
RUN groupadd -g 10001 orin && \
    useradd -u 10001 -g orin -m -s /sbin/nologin orin && \
    mkdir -p /var/lib/orin /etc/orin && \
    chown -R orin:orin /var/lib/orin /etc/orin /app

# Switch to the non-root user
USER orin

# Expose the default Orin Hub port
EXPOSE 8000

CMD ["orin", "-d", "/var/lib/orin/orin_vault.db", "hub-serve", "8000", "--host", "0.0.0.0"]

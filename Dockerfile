# Dockerfile untuk Aplikasi Flask Genset
# Base image dengan Python 3.11 slim untuk ukuran yang optimal
FROM python:3.11-slim

# Maintainer information
LABEL maintainer="genset-app@example.com"
LABEL version="1.0.0"
LABEL description="Flask Application for Genset Management System"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=Main.py
ENV FLASK_ENV=production
ENV FLASK_DEBUG=0

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user untuk security
RUN groupadd -r gensetuser && useradd -r -g gensetuser gensetuser

# Copy requirements terlebih dahulu untuk leverage Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs \
    && mkdir -p /app/data \
    && mkdir -p /app/uploads

# Set proper permissions
RUN chown -R gensetuser:gensetuser /app \
    && chmod -R 755 /app

# Create health check script
RUN echo '#!/bin/bash\ncurl -f http://localhost:5000/api/status || exit 1' > /app/healthcheck.sh \
    && chmod +x /app/healthcheck.sh

# Switch to non-root user
USER gensetuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /app/healthcheck.sh

# Volume untuk persistent data
VOLUME ["/app/data", "/app/logs"]

# Default command
CMD ["python", "Main.py"]

# Alternative commands (uncomment untuk production dengan Gunicorn)
# CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "Main:app"]
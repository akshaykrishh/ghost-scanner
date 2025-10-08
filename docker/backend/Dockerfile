# Ghost Scanner Backend Dockerfile

FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    curl \
    jq \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Gitleaks
RUN curl -sSfL https://github.com/zricethezav/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | \
    tar -xz -C /usr/local/bin && \
    chmod +x /usr/local/bin/gitleaks

# Install OWASP Dependency-Check
RUN curl -sSfL https://github.com/jeremylong/DependencyCheck/releases/download/v8.4.0/dependency-check-8.4.0-release.zip -o /tmp/dependency-check.zip && \
    unzip /tmp/dependency-check.zip -d /opt/ && \
    chmod +x /opt/dependency-check/bin/dependency-check.sh && \
    ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check && \
    rm /tmp/dependency-check.zip

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY backend/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ .

# Add the current directory to Python path
ENV PYTHONPATH=/app

# Create necessary directories
RUN mkdir -p logs data models temp

# Create non-root user
RUN useradd --create-home --shell /bin/bash ghostscanner && \
    chown -R ghostscanner:ghostscanner /app
USER ghostscanner

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

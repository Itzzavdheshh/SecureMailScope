FROM python:3.12-slim

LABEL maintainer="SecureMailScope Team"
LABEL description="SecureMailScope Backend API — PCAP cryptographic analysis"

# Security: run as non-root
RUN addgroup --system sms && adduser --system --group sms

WORKDIR /app

# Install system dependencies for scapy/dpkt on Linux
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy rules from project root (passed via build context)
COPY rules ./rules

# Create upload directory with correct ownership
RUN mkdir -p /app/uploads && chown sms:sms /app/uploads

USER sms

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/api/health').raise_for_status()"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-config", "none"]

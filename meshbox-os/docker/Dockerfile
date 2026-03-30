FROM python:3.12-slim

# Install Tor
RUN apt-get update && \
    apt-get install -y --no-install-recommends tor && \
    rm -rf /var/lib/apt/lists/*

# Create meshbox user
RUN useradd -m -s /bin/bash meshbox

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY meshbox-os/meshbox/ /app/meshbox/

# Data directory
VOLUME ["/home/meshbox/.meshbox"]

# SANP protocol port + API port
EXPOSE 7777 8080

USER meshbox

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health')" || exit 1

CMD ["python", "-m", "meshbox.main"]

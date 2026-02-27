FROM python:3.12-slim

LABEL maintainer="DJAM Foundation / IA Commune Algeria"
LABEL version="2.0.0"

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY . .

# Non-root user
RUN useradd -m -u 1000 earthflow && chown -R earthflow:earthflow /app
USER earthflow

EXPOSE 8443 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python scripts/healthcheck.py --host localhost --port 8443 || exit 1

CMD ["python", "-m", "uvicorn", "proxy.server:app", "--host", "0.0.0.0", "--port", "8443"]

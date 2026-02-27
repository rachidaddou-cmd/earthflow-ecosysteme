# Earthflow Écosystème — Deployment Guide

**Version:** 2.0.0  
**Environments:** Docker (recommended), bare-metal Linux, Kubernetes

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Quick Start — Docker Compose](#2-quick-start--docker-compose)
3. [Configuration Reference](#3-configuration-reference)
4. [Production Deployment](#4-production-deployment)
5. [Kubernetes Deployment](#5-kubernetes-deployment)
6. [TLS / HTTPS](#6-tls--https)
7. [Key Rotation](#7-key-rotation)
8. [Log Migration](#8-log-migration)
9. [Monitoring & Alerting](#9-monitoring--alerting)
10. [Backup & Recovery](#10-backup--recovery)
11. [Hardening Checklist](#11-hardening-checklist)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 2 GB | 8 GB |
| Disk | 20 GB | 100 GB SSD |
| OS | Ubuntu 22.04 | Ubuntu 24.04 |
| Docker | 24.x | 26.x |
| Docker Compose | 2.x | 2.24+ |
| Python | 3.10 | 3.12 |

**Required open ports:**

| Port | Service | Exposure |
|---|---|---|
| 8443 | Proxy / API (HTTPS) | Public (restricted) |
| 8080 | Dashboard (HTTP) | Internal only |
| 5432 | PostgreSQL | Internal only |
| 6379 | Redis | Internal only |

---

## 2. Quick Start — Docker Compose

### 2.1 Clone and configure

```bash
git clone https://github.com/earthflow/earthflow-ecosysteme.git
cd earthflow-ecosysteme

# Copy and edit the environment file
cp .env.example .env
nano .env
```

Minimum required variables:

```env
EARTHFLOW_MASTER_KEY=<generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
EARTHFLOW_ADMIN_API_KEY=<your-secure-admin-key>
POSTGRES_PASSWORD=<strong-password>
```

### 2.2 Start services

```bash
docker compose up -d
```

This starts:

- `earthflow-proxy` — AI request interception on port 8443
- `earthflow-dashboard` — Monitoring UI on port 8080
- `postgres` — Audit log persistence
- `redis` — Rate limiter state and session cache

### 2.3 Verify

```bash
curl http://localhost:8443/health
# {"status":"OK","version":"2.0.0",...}
```

### 2.4 Create your first tenant

```bash
curl -X POST http://localhost:8443/v1/tenants \
  -H "X-API-Key: $EARTHFLOW_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Organization", "rules_preset": "default"}'
```

Save the returned `api_key` — it is shown only once.

---

## 3. Configuration Reference

All configuration is via environment variables. Copy `.env.example` as your starting point.

### Core

| Variable | Default | Description |
|---|---|---|
| `EARTHFLOW_MASTER_KEY` | — | **Required.** Fernet master key for encryption at rest |
| `EARTHFLOW_ADMIN_API_KEY` | — | **Required.** Admin API key |
| `EARTHFLOW_ENV` | `production` | Environment: `development`, `staging`, `production` |
| `EARTHFLOW_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `EARTHFLOW_PORT` | `8443` | Proxy listening port |

### Database

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_HOST` | `postgres` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_DB` | `earthflow` | Database name |
| `POSTGRES_USER` | `earthflow` | Database user |
| `POSTGRES_PASSWORD` | — | **Required.** Database password |

### Redis

| Variable | Default | Description |
|---|---|---|
| `REDIS_HOST` | `redis` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | — | Redis password (recommended in production) |
| `REDIS_TLS` | `false` | Enable TLS for Redis connection |

### Rate Limiting

| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_DEFAULT_RPM` | `1000` | Default requests per minute per tenant |
| `RATE_LIMIT_BURST_FACTOR` | `1.5` | Burst multiplier |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Token bucket refill window |

### TLS

| Variable | Default | Description |
|---|---|---|
| `TLS_CERT_PATH` | — | Path to TLS certificate (PEM) |
| `TLS_KEY_PATH` | — | Path to TLS private key (PEM) |
| `TLS_CA_PATH` | — | Optional CA bundle for mTLS |

### Webhook Delivery

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_MAX_RETRIES` | `3` | Retry attempts on delivery failure |
| `WEBHOOK_TIMEOUT_SECONDS` | `5` | HTTP timeout per attempt |
| `WEBHOOK_RETRY_BACKOFF_MS` | `500` | Initial backoff (doubles each retry) |

### Audit

| Variable | Default | Description |
|---|---|---|
| `AUDIT_RETENTION_DAYS` | `365` | Days to retain audit records |
| `AUDIT_HASH_PROMPTS` | `true` | Store only SHA-256 of prompt content |

---

## 4. Production Deployment

### 4.1 Bare-metal / VM

```bash
# Install Python dependencies
pip install -r requirements.txt --break-system-packages

# Set up PostgreSQL and Redis separately, then:
python -m earthflow.proxy.server &
python -m earthflow.dashboard.server &
```

Use `systemd` service units for process management:

```ini
# /etc/systemd/system/earthflow-proxy.service
[Unit]
Description=Earthflow Proxy
After=network.target postgresql.service redis.service

[Service]
User=earthflow
WorkingDirectory=/opt/earthflow
EnvironmentFile=/opt/earthflow/.env
ExecStart=/usr/bin/python3 -m earthflow.proxy.server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now earthflow-proxy
```

### 4.2 Docker (production hardening)

```bash
# Use specific image tags — never use :latest in production
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Recommended `docker-compose.prod.yml` overrides:

```yaml
services:
  earthflow-proxy:
    restart: always
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
```

---

## 5. Kubernetes Deployment

### 5.1 Namespace and secrets

```bash
kubectl create namespace earthflow

kubectl create secret generic earthflow-secrets \
  --from-literal=master-key="$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")" \
  --from-literal=admin-api-key="your-admin-key" \
  --from-literal=postgres-password="your-db-password" \
  -n earthflow
```

### 5.2 Deployment manifest (proxy)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: earthflow-proxy
  namespace: earthflow
spec:
  replicas: 2
  selector:
    matchLabels:
      app: earthflow-proxy
  template:
    metadata:
      labels:
        app: earthflow-proxy
    spec:
      containers:
        - name: proxy
          image: earthflow/proxy:2.0.0
          ports:
            - containerPort: 8443
          envFrom:
            - secretRef:
                name: earthflow-secrets
          livenessProbe:
            httpGet:
              path: /health
              port: 8443
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 8443
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: "500m"
              memory: "512Mi"
            limits:
              cpu: "2"
              memory: "4Gi"
          securityContext:
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 1000
```

### 5.3 Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: earthflow-proxy-hpa
  namespace: earthflow
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: earthflow-proxy
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

---

## 6. TLS / HTTPS

### 6.1 Self-signed (development only)

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes \
  -subj "/CN=earthflow-proxy"
```

### 6.2 Let's Encrypt (production)

```bash
certbot certonly --standalone -d your-domain.com
# Certificates saved to /etc/letsencrypt/live/your-domain.com/
```

Set in `.env`:

```env
TLS_CERT_PATH=/etc/letsencrypt/live/your-domain.com/fullchain.pem
TLS_KEY_PATH=/etc/letsencrypt/live/your-domain.com/privkey.pem
```

Auto-renewal via cron:

```bash
0 2 * * * certbot renew --quiet && docker compose restart earthflow-proxy
```

---

## 7. Key Rotation

### 7.1 Manual rotation

```bash
python scripts/rotate_keys.py --tenant-id t1
```

Options:

```
--tenant-id     Rotate keys for specific tenant (omit = all tenants)
--revoke-after  Seconds before old key is invalidated (default: 3600)
--dry-run       Preview rotation without applying
```

### 7.2 Scheduled rotation (cron)

```bash
# Rotate all tenant keys monthly
0 3 1 * * cd /opt/earthflow && python scripts/rotate_keys.py --revoke-after 3600
```

### 7.3 Master key rotation

```bash
# Generate new master key
NEW_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Re-encrypt all stored secrets with new key
python scripts/rotate_keys.py --rotate-master --new-key "$NEW_KEY"

# Update .env
sed -i "s/^EARTHFLOW_MASTER_KEY=.*/EARTHFLOW_MASTER_KEY=$NEW_KEY/" .env

# Restart services
docker compose restart
```

---

## 8. Log Migration

When upgrading from v1.x to v2.x, audit log format changes require migration.

```bash
python scripts/migrate_logs.py \
  --from-version 1 \
  --to-version 2 \
  --input /var/earthflow/audit_v1.jsonl \
  --output /var/earthflow/audit_v2.jsonl \
  --dry-run
```

Remove `--dry-run` to apply. Always back up before migrating:

```bash
cp /var/earthflow/audit_v1.jsonl /var/earthflow/audit_v1.jsonl.bak
```

---

## 9. Monitoring & Alerting

### 9.1 Prometheus

Metrics are exposed at `GET /v1/dashboard/metrics` in Prometheus text format.

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'earthflow'
    static_configs:
      - targets: ['earthflow-proxy:8443']
    metrics_path: '/v1/dashboard/metrics'
    bearer_token: '<your-admin-key>'
```

### 9.2 Key metrics to alert on

| Metric | Alert Threshold | Severity |
|---|---|---|
| `earthflow_block_rate` | > 10% over 5 min | WARNING |
| `earthflow_block_rate` | > 30% over 1 min | CRITICAL |
| `earthflow_error_rate` | > 1% over 5 min | WARNING |
| `earthflow_latency_p99_ms` | > 500 ms | WARNING |
| `earthflow_rule_violations_total` | Sudden spike | INFO |

### 9.3 Health checks

```bash
# Liveness
curl https://your-host:8443/health

# Readiness (checks all subsystems)
curl https://your-host:8443/health/ready

# Scripted check
python scripts/healthcheck.py --host your-host --port 8443
```

---

## 10. Backup & Recovery

### 10.1 Database backup

```bash
# Daily backup (add to cron)
docker exec earthflow-postgres pg_dump -U earthflow earthflow \
  | gzip > /backups/earthflow_$(date +%Y%m%d).sql.gz

# Retain last 30 days
find /backups -name "earthflow_*.sql.gz" -mtime +30 -delete
```

### 10.2 Restore

```bash
gunzip -c /backups/earthflow_20250201.sql.gz \
  | docker exec -i earthflow-postgres psql -U earthflow earthflow
```

### 10.3 Configuration backup

```bash
# Back up rules and tenant configuration
curl -H "X-API-Key: $ADMIN_KEY" https://your-host:8443/v1/rules \
  > backup/rules_$(date +%Y%m%d).json

curl -H "X-API-Key: $ADMIN_KEY" https://your-host:8443/v1/tenants \
  > backup/tenants_$(date +%Y%m%d).json
```

---

## 11. Hardening Checklist

Before going live, verify each item:

```
[ ] EARTHFLOW_MASTER_KEY is at least 32 bytes, stored in a secret manager
[ ] EARTHFLOW_ADMIN_API_KEY is not the default value
[ ] POSTGRES_PASSWORD is strong (16+ chars, mixed case, symbols)
[ ] TLS is enabled (TLS_CERT_PATH and TLS_KEY_PATH are set)
[ ] Dashboard port 8080 is not publicly accessible
[ ] Redis is password-protected (REDIS_PASSWORD is set)
[ ] AUDIT_HASH_PROMPTS=true (never store raw prompt content)
[ ] Docker containers run as non-root
[ ] read_only: true on all containers
[ ] Rate limits are set per tenant
[ ] Webhook endpoints use HTTPS only
[ ] Key rotation is scheduled (monthly minimum)
[ ] Database backups are scheduled and tested
[ ] Prometheus alerts are configured
[ ] SECURITY.md has been read by the operations team
[ ] CI/CD pipeline runs test suite on every push
```

---

## 12. Troubleshooting

### Service fails to start

```bash
docker compose logs earthflow-proxy
```

Common causes:

- `EARTHFLOW_MASTER_KEY` not set or invalid Fernet key format
- PostgreSQL not reachable (check `POSTGRES_HOST`)
- Port 8443 already in use: `lsof -i :8443`

### All requests return 401

- Verify the API key matches one registered for the tenant
- Check the key has not been revoked: `GET /v1/tenants/{id}`
- Confirm the `Authorization` or `X-API-Key` header is being sent

### High block rate unexpectedly

```bash
# Check which rules are triggering
curl -H "X-API-Key: $KEY" \
  "https://your-host:8443/v1/audit/stats?from=2025-02-01T00:00:00Z"
```

Review `top_triggered_rules` and adjust rule priority or conditions.

### Rate limit errors (429) in normal operation

Increase tenant limit:

```bash
curl -X PATCH https://your-host:8443/v1/tenants/t1 \
  -H "X-API-Key: $ADMIN_KEY" \
  -d '{"max_requests_per_minute": 5000}'
```

### Webhook deliveries failing

```bash
# Check delivery log via audit
curl -H "X-API-Key: $KEY" \
  "https://your-host:8443/v1/audit?status=BLOCK&limit=5"
```

Ensure the webhook endpoint is reachable from the Earthflow container network and returns 2xx within the timeout window.

---

*Earthflow Écosystème — © DJAM Foundation / IA Commune Algeria. All rights reserved.*

# Earthflow Écosystème — API Reference

**Version:** 2.0.0  
**Base URL:** `https://your-host:8443`  
**Auth:** Bearer token via `Authorization` header or `X-API-Key` header  
**Format:** JSON (all requests and responses)

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [Proxy — AI Request Interception](#2-proxy--ai-request-interception)
3. [Rules Engine](#3-rules-engine)
4. [Audit Logs](#4-audit-logs)
5. [Webhooks](#5-webhooks)
6. [Multi-Tenant Management](#6-multi-tenant-management)
7. [Rate Limiting](#7-rate-limiting)
8. [Dashboard](#8-dashboard)
9. [Health & Ops](#9-health--ops)
10. [Error Reference](#10-error-reference)
11. [SDK Quick Reference](#11-sdk-quick-reference)

---

## 1. Authentication

All requests must include a valid API key issued during tenant registration.

### Headers

```
Authorization: Bearer <api_key>
```

or

```
X-API-Key: <api_key>
```

### Key Scopes

| Scope | Description |
|---|---|
| `proxy:write` | Submit AI requests through the proxy |
| `rules:read` | Read rule configurations |
| `rules:write` | Create / update / delete rules |
| `audit:read` | Access audit logs |
| `admin` | Full access, including tenant management |

---

## 2. Proxy — AI Request Interception

The proxy intercepts AI requests, evaluates them against configured rules, and forwards or blocks them accordingly.

### POST /v1/proxy

Submit a request to be evaluated and optionally forwarded to a downstream AI provider.

**Request**

```json
{
  "model": "gpt-4",
  "messages": [
    { "role": "user", "content": "Analyse this patient record: John Doe, SSN 123-45-6789..." }
  ],
  "metadata": {
    "user_id": "user_42",
    "session_id": "sess_abc123",
    "department": "radiology"
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `model` | string | yes | Target model identifier |
| `messages` | array | yes | Conversation messages |
| `metadata` | object | no | Contextual data passed to rule engine |

**Response — ALLOW**

```json
{
  "status": "ALLOW",
  "request_id": "req_7f3a9b",
  "forwarded": true,
  "response": { ... },
  "audit_id": "aud_001abc",
  "rules_evaluated": 12,
  "rules_triggered": 0,
  "latency_ms": 43
}
```

**Response — BLOCK**

```json
{
  "status": "BLOCK",
  "request_id": "req_7f3a9c",
  "forwarded": false,
  "reason": "PII detected in prompt (rule: pii_block_ssn)",
  "audit_id": "aud_001abd",
  "rules_triggered": 1,
  "triggered_rules": [
    {
      "rule_id": "pii_block_ssn",
      "name": "Block SSN in prompt",
      "action": "BLOCK",
      "matched_field": "messages[0].content"
    }
  ]
}
```

**Response — REDACT**

```json
{
  "status": "REDACT",
  "request_id": "req_7f3a9d",
  "forwarded": true,
  "redactions": [
    { "field": "messages[0].content", "pattern": "SSN", "replacement": "[SSN]" }
  ],
  "response": { ... }
}
```

**HTTP Status Codes**

| Code | Meaning |
|---|---|
| 200 | Request processed (check `status` field for outcome) |
| 400 | Malformed request |
| 401 | Authentication failed |
| 422 | Request structure invalid |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

---

## 3. Rules Engine

### GET /v1/rules

List all rules for the authenticated tenant.

**Query Parameters**

| Param | Type | Default | Description |
|---|---|---|---|
| `preset` | string | — | Filter by preset name |
| `action` | string | — | Filter by action (ALLOW, BLOCK, WARN, REDACT, ESCALATE) |
| `active` | boolean | true | Include only active rules |
| `limit` | int | 50 | Max results |
| `offset` | int | 0 | Pagination offset |

**Response**

```json
{
  "rules": [
    {
      "id": "rule_001",
      "name": "Block SSN in prompt",
      "condition": {
        "operator": "regex",
        "value": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
        "target": "prompt"
      },
      "action": "BLOCK",
      "priority": 90,
      "active": true,
      "preset": "medical",
      "created_at": "2025-01-15T10:00:00Z",
      "updated_at": "2025-01-20T08:30:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

---

### GET /v1/rules/{rule_id}

Retrieve a single rule.

**Response**

```json
{
  "id": "rule_001",
  "name": "Block SSN in prompt",
  "condition": { ... },
  "action": "BLOCK",
  "priority": 90,
  "active": true,
  "metadata": { "eu_ai_act_article": "Article 9" }
}
```

---

### POST /v1/rules

Create a new rule.

**Request**

```json
{
  "name": "Warn on competitor mention",
  "condition": {
    "operator": "contains",
    "value": "CompetitorName",
    "target": "prompt",
    "case_sensitive": false
  },
  "action": "WARN",
  "priority": 40,
  "metadata": {
    "description": "Flag mentions of competitor for review"
  }
}
```

**Condition Operators**

| Operator | Description | Value Type |
|---|---|---|
| `contains` | String contains value | string |
| `not_contains` | String does not contain value | string |
| `regex` | Regular expression match | string (regex) |
| `threshold` | Numeric comparison | `{"op": ">", "value": 0.8}` |
| `equals` | Exact equality | any |
| `not_equals` | Inequality | any |
| `length_gt` | String length greater than | int |
| `length_lt` | String length less than | int |

**Valid Actions**

| Action | Behavior |
|---|---|
| `ALLOW` | Explicitly permit the request |
| `BLOCK` | Reject the request immediately |
| `WARN` | Log a warning, continue processing |
| `REDACT` | Replace matched content, then forward |
| `ESCALATE` | Route to human review queue |

**Response** — `201 Created`

```json
{ "id": "rule_002", "created_at": "2025-02-01T12:00:00Z", ... }
```

---

### PUT /v1/rules/{rule_id}

Update an existing rule (full replace).

**Request** — same structure as POST.

**Response** — `200 OK` with updated rule.

---

### PATCH /v1/rules/{rule_id}

Partial update.

```json
{ "active": false }
```

---

### DELETE /v1/rules/{rule_id}

Soft-delete a rule (sets `active: false`).

**Response** — `204 No Content`

---

### GET /v1/rules/presets

List available presets.

**Response**

```json
{
  "presets": ["default", "medical", "financial", "hr"],
  "descriptions": {
    "medical": "HIPAA + EU AI Act Art. 22 compliant rules",
    "financial": "MiFID II + GDPR Article 22 compliant rules",
    "hr": "Anti-discrimination and bias detection rules"
  }
}
```

---

### POST /v1/rules/presets/{preset}/apply

Apply a preset to the tenant, replacing or merging existing rules.

**Request**

```json
{ "mode": "merge" }
```

`mode`: `"replace"` (default) or `"merge"`

**Response** — `200 OK`

```json
{ "applied": 8, "skipped": 0, "preset": "medical" }
```

---

## 4. Audit Logs

### GET /v1/audit

Query the audit log.

**Query Parameters**

| Param | Type | Description |
|---|---|---|
| `from` | ISO 8601 | Start timestamp |
| `to` | ISO 8601 | End timestamp |
| `status` | string | Filter by outcome: ALLOW, BLOCK, WARN, REDACT |
| `rule_id` | string | Filter by rule that triggered |
| `user_id` | string | Filter by metadata.user_id |
| `limit` | int | Default 100, max 1000 |
| `offset` | int | Pagination |

**Response**

```json
{
  "entries": [
    {
      "audit_id": "aud_001abc",
      "request_id": "req_7f3a9b",
      "tenant_id": "t1",
      "timestamp": "2025-02-01T14:23:11Z",
      "status": "BLOCK",
      "model": "gpt-4",
      "rules_evaluated": 12,
      "rules_triggered": ["rule_001"],
      "metadata": { "user_id": "user_42", "department": "radiology" },
      "latency_ms": 8,
      "prompt_hash": "sha256:3f7a9b..."
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

> **Note:** Prompt content is never stored in audit logs. Only a SHA-256 hash is retained for integrity verification.

---

### GET /v1/audit/{audit_id}

Retrieve a single audit entry.

---

### GET /v1/audit/stats

Aggregate statistics over a time window.

**Query Parameters:** `from`, `to`, `group_by` (hour | day | week)

**Response**

```json
{
  "period": { "from": "2025-01-01T00:00:00Z", "to": "2025-02-01T00:00:00Z" },
  "totals": {
    "requests": 84200,
    "allowed": 80100,
    "blocked": 3200,
    "warned": 600,
    "redacted": 300
  },
  "block_rate": 0.038,
  "top_triggered_rules": [
    { "rule_id": "rule_001", "count": 1840, "name": "Block SSN in prompt" }
  ],
  "series": [
    { "ts": "2025-01-01T00:00:00Z", "requests": 2800, "blocked": 92 }
  ]
}
```

---

## 5. Webhooks

### GET /v1/webhooks

List registered webhook endpoints.

---

### POST /v1/webhooks

Register a new webhook.

**Request**

```json
{
  "url": "https://siem.hospital.com/earthflow",
  "secret": "your_signing_secret",
  "events": ["BLOCK", "ESCALATE"],
  "active": true
}
```

| Field | Description |
|---|---|
| `url` | HTTPS endpoint to receive events |
| `secret` | Used to sign payloads (HMAC-SHA256) |
| `events` | Array of event types to subscribe to |

**Event Types:** `ALLOW`, `BLOCK`, `WARN`, `REDACT`, `ESCALATE`, `RULE_TRIGGERED`, `RATE_LIMIT_HIT`

---

### Webhook Payload

```json
{
  "event": "BLOCK",
  "request_id": "req_7f3a9c",
  "tenant_id": "t1",
  "timestamp": "2025-02-01T14:23:11Z",
  "data": {
    "rule_id": "rule_001",
    "model": "gpt-4",
    "metadata": { "user_id": "user_42" }
  }
}
```

### Signature Verification

Every webhook includes the header:

```
X-Earthflow-Signature: sha256=<hmac_hex>
```

Verify in Python:

```python
import hmac, hashlib

def verify(payload: str, header: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header)
```

---

### DELETE /v1/webhooks/{webhook_id}

Remove a webhook registration.

---

## 6. Multi-Tenant Management

> Requires `admin` scope.

### GET /v1/tenants

List all tenants.

**Response**

```json
{
  "tenants": [
    {
      "tenant_id": "t1",
      "name": "Hospital A",
      "rules_preset": "medical",
      "active": true,
      "created_at": "2025-01-01T00:00:00Z",
      "api_key_count": 3
    }
  ]
}
```

---

### POST /v1/tenants

Register a new tenant.

**Request**

```json
{
  "name": "Bank B",
  "rules_preset": "financial",
  "max_requests_per_minute": 5000,
  "contact_email": "admin@bankb.com"
}
```

**Response** — `201 Created`

```json
{
  "tenant_id": "t2",
  "api_key": "ef_live_xxxxxxxxxxxxxxxxxxxx",
  "created_at": "2025-02-01T09:00:00Z"
}
```

> **Important:** The `api_key` is returned only once. Store it securely.

---

### GET /v1/tenants/{tenant_id}

Retrieve tenant details.

---

### PATCH /v1/tenants/{tenant_id}

Update tenant configuration.

```json
{ "max_requests_per_minute": 10000 }
```

---

### DELETE /v1/tenants/{tenant_id}

Deactivate a tenant (soft delete). All associated keys are revoked.

---

### POST /v1/tenants/{tenant_id}/keys

Generate a new API key for a tenant.

**Response**

```json
{ "api_key": "ef_live_yyyyyyyyyyyyyyyyyyyy", "created_at": "..." }
```

---

### DELETE /v1/tenants/{tenant_id}/keys/{key_prefix}

Revoke a specific API key.

---

## 7. Rate Limiting

Rate limiting uses a **token bucket** algorithm, configurable per tenant.

### Default Limits

| Plan | Requests/minute | Burst |
|---|---|---|
| Standard | 1 000 | 1 500 |
| Professional | 10 000 | 15 000 |
| Enterprise | unlimited | — |

### Headers Returned on Every Response

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1706784060
```

### 429 Response

```json
{
  "error": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded for tenant 't1' (limit: 1000/min)",
  "retry_after_seconds": 12
}
```

---

## 8. Dashboard

The dashboard exposes read-only aggregated metrics.

### GET /v1/dashboard/summary

**Response**

```json
{
  "period_24h": {
    "requests": 18400,
    "blocked": 320,
    "warned": 88,
    "block_rate": 0.017
  },
  "active_tenants": 4,
  "active_rules": 34,
  "top_rules": [ ... ],
  "system_health": "OK"
}
```

### GET /v1/dashboard/metrics

Prometheus-compatible metrics endpoint.

```
# HELP earthflow_requests_total Total AI requests processed
# TYPE earthflow_requests_total counter
earthflow_requests_total{status="ALLOW",tenant="t1"} 80100
earthflow_requests_total{status="BLOCK",tenant="t1"} 3200
```

---

## 9. Health & Ops

### GET /health

Basic liveness check.

```json
{ "status": "OK", "version": "2.0.0", "uptime_seconds": 86400 }
```

### GET /health/ready

Readiness check (verifies database, crypto subsystem).

```json
{
  "status": "OK",
  "checks": {
    "database": "OK",
    "crypto": "OK",
    "rules_engine": "OK"
  }
}
```

### POST /v1/ops/rotate-keys

Trigger key rotation (admin only).

```json
{ "tenant_id": "t1", "revoke_old_after_seconds": 3600 }
```

---

## 10. Error Reference

All errors follow this structure:

```json
{
  "error": "ERROR_CODE",
  "message": "Human-readable description",
  "context": { "field": "value" },
  "timestamp": "2025-02-01T14:23:11Z",
  "request_id": "req_7f3a9c"
}
```

### Error Codes

| Code | HTTP | Description |
|---|---|---|
| `AUTH_ERROR` | 401 | Invalid or missing API key |
| `TENANT_NOT_FOUND` | 404 | Tenant does not exist |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `STOP_CONDITION_TRIGGERED` | 200 | Rule triggered a stop action |
| `POLICY_VIOLATION` | 200 | EU AI Act or custom policy violated |
| `CONFIG_ERROR` | 422 | Invalid rule or configuration |
| `VALIDATION_ERROR` | 400 | Request body validation failed |
| `EARTHFLOW_ERROR` | 500 | Internal server error |

---

## 11. SDK Quick Reference

### JavaScript / TypeScript

```javascript
import { EarthflowClient } from '@earthflow/sdk';

const client = new EarthflowClient({
  apiKey: process.env.EARTHFLOW_API_KEY,
  baseUrl: 'https://your-host:8443'
});

const result = await client.proxy({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello' }],
  metadata: { userId: 'u1' }
});

if (result.status === 'ALLOW') {
  console.log(result.response);
} else {
  console.warn('Blocked:', result.reason);
}
```

### Java

```java
EarthflowClient client = new EarthflowClient.Builder()
    .apiKey(System.getenv("EARTHFLOW_API_KEY"))
    .baseUrl("https://your-host:8443")
    .build();

ProxyRequest req = new ProxyRequest("gpt-4", messages);
ProxyResponse resp = client.proxy(req);

if (resp.getStatus().equals("ALLOW")) {
    System.out.println(resp.getResponse());
}
```

### C#

```csharp
var client = new EarthflowClient(
    apiKey: Environment.GetEnvironmentVariable("EARTHFLOW_API_KEY"),
    baseUrl: "https://your-host:8443"
);

var result = await client.ProxyAsync(new ProxyRequest {
    Model = "gpt-4",
    Messages = messages
});
```

### Python (requests)

```python
import os, requests

resp = requests.post(
    "https://your-host:8443/v1/proxy",
    headers={"X-API-Key": os.environ["EARTHFLOW_API_KEY"]},
    json={
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello"}]
    }
)
data = resp.json()
print(data["status"])  # ALLOW | BLOCK | WARN | REDACT
```

---

*Earthflow Écosystème — © DJAM Foundation / IA Commune Algeria. All rights reserved.*

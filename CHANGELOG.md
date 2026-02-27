# Changelog

All notable changes to Earthflow Écosystème are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
This project uses [Semantic Versioning](https://semver.org/).

---

## [2.0.0] — 2025-02-27

### Added
- `core/crypto.py` — AES-256 encryption (Fernet), PBKDF2 key derivation, HMAC-SHA256 signing, key rotation
- `core/window.py` — Thread-safe sliding time window (count, sum, average)
- `core/webhook.py` — HMAC-signed webhook delivery with exponential retry
- `core/multitenant.py` — Full tenant isolation, API key routing, key revocation
- `core/rate_limiter.py` — Token bucket rate limiter, per-tenant, with cost parameter
- `core/anonymizer.py` — PII detection and redaction (email, phone, SSN, IP, credit card)
- `rules/validator.py` — Rule and preset schema validation with structured errors
- `stop/exceptions.py` — Complete exception hierarchy (StopConditionTriggered, PolicyViolation, AuthenticationError, TenantNotFound, RateLimitExceeded, ConfigurationError)
- `tests/test_suite_v2.py` — 70 new tests covering all v2.0 modules
- `scripts/migrate_logs.py` — Audit log migration v1→v2 with dry-run, backup, self-test
- `examples/sectors/hr_demo.py` — HR governance demo (anti-discrimination, pay equity)
- `docs/API_REFERENCE.md` — Complete API reference (11 sections)
- `docs/DEPLOYMENT.md` — Deployment guide (12 sections, Docker, Kubernetes, TLS, hardening)
- `.github/ISSUE_TEMPLATE/bug_report.md` — Structured bug report template
- `.github/ISSUE_TEMPLATE/feature_request.md` — Feature request template with regulatory fields
- `LICENSE` — Apache License 2.0
- `NOTICE` — Copyright attribution
- `README.md` — Project overview, quickstart, architecture diagram
- `CONTRIBUTING.md` — Contribution guide
- `CHANGELOG.md` — This file

### Changed
- `stop/exceptions.py` — Replaced `datetime.utcnow()` with timezone-aware `datetime.now(tz=timezone.utc)`
- `core/multitenant.py` — Same timezone fix

### Security
- Prompts are never stored — only SHA-256 hashes retained in audit log
- All API keys encrypted at rest with Fernet (AES-256-CBC + HMAC-SHA256)
- Webhook payloads signed with HMAC-SHA256

---

## [1.0.0] — 2025-01-15

### Added
- `core/audit.py` — Immutable audit log with SHA-256 prompt hashing
- `rules/engine.py` — Rule evaluation engine (8 operators)
- `rules/eu_ai_act_rules.json` — EU AI Act compliance rules
- `rules/presets/` — medical, financial, hr presets
- `stop/controller.py` — Stop condition controller
- `proxy/server.py` — FastAPI AI proxy server
- `proxy/middleware.py` — Request logging and correlation ID middleware
- `dashboard/server.py` — Read-only metrics dashboard with Prometheus endpoint
- `sdk/js/earthflow.js` — JavaScript/TypeScript SDK
- `sdk/java/EarthflowClient.java` — Java SDK
- `sdk/cs/EarthflowClient.cs` — C# SDK
- `tests/test_suite.py` — 21 tests (audit, rules engine, stop controller)
- `scripts/healthcheck.py` — Liveness and readiness check
- `scripts/rotate_keys.py` — API key and master key rotation
- `examples/quickstart.py` — 5-minute quickstart
- `examples/sectors/medical_demo.py` — Medical sector demo
- `examples/sectors/financial_demo.py` — Financial sector demo
- `Dockerfile` — Python 3.12, non-root, integrated healthcheck
- `docker-compose.yml` — proxy + dashboard + PostgreSQL + Redis
- `.env.example` — All environment variables documented
- `SECURITY.md` — Responsible disclosure policy
- `.github/workflows/ci.yml` — GitHub Actions CI (test + lint)

---

[2.0.0]: https://github.com/earthflow/earthflow-ecosysteme/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/earthflow/earthflow-ecosysteme/releases/tag/v1.0.0

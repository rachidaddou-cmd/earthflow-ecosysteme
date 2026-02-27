# Earthflow Écosystème

[![CI](https://github.com/earthflow/earthflow-ecosysteme/actions/workflows/ci.yml/badge.svg)](https://github.com/earthflow/earthflow-ecosysteme/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![Version](https://img.shields.io/badge/version-2.0.0-green)](CHANGELOG.md)

**Earthflow Écosystème** is an open-source AI governance proxy for industrial deployments. It intercepts AI requests in real time, evaluates them against configurable compliance rules, and enforces ALLOW / BLOCK / WARN / REDACT / ESCALATE decisions — before any prompt reaches an AI model.

Built by [DJAM Foundation](https://djam.foundation) / [IA Commune Algeria](https://iacommune.dz), Perpignan.

---

## Why Earthflow?

AI governance is not optional. The EU AI Act, GDPR Article 22, HIPAA, and MiFID II all impose constraints on automated decision-making. Earthflow gives organisations a single, auditable control point between their users and any AI model.

- **Sector presets** — medical, financial, HR rules out of the box
- **Multi-tenant** — full isolation per organisation, per API key
- **Audit trail** — every request logged, prompts hashed (never stored)
- **SDK** — JavaScript, Java, C# clients included
- **Open standard** — Apache 2.0, no vendor lock-in

---

## Quickstart

```bash
# 1. Clone
git clone https://github.com/earthflow/earthflow-ecosysteme.git
cd earthflow-ecosysteme

# 2. Configure
cp .env.example .env
# Edit .env — set EARTHFLOW_MASTER_KEY, EARTHFLOW_ADMIN_API_KEY, POSTGRES_PASSWORD

# 3. Start
docker compose up -d

# 4. Verify
curl http://localhost:8443/health
```

Create your first tenant:

```bash
curl -X POST http://localhost:8443/v1/tenants \
  -H "X-API-Key: $EARTHFLOW_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Organisation", "rules_preset": "medical"}'
```

Run the Python quickstart:

```bash
pip install -r requirements.txt
python examples/quickstart.py
```

---

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────────┐
│   Client    │────▶│              Earthflow Proxy              │
│ (any SDK)   │     │                                          │
└─────────────┘     │  ┌──────────┐  ┌──────────┐  ┌───────┐  │
                    │  │  Rules   │  │   Stop   │  │ Audit │  │
                    │  │  Engine  │  │Controller│  │  Log  │  │
                    │  └──────────┘  └──────────┘  └───────┘  │
                    │       │              │                    │
                    │  ALLOW│         BLOCK│ESCALATE            │
                    └───────┼─────────────┼────────────────────┘
                            ▼             ▼
                       AI Provider    Human Review
```

---

## Rule Actions

| Action | Behaviour |
|---|---|
| `ALLOW` | Forward to AI model |
| `BLOCK` | Reject immediately |
| `WARN` | Log warning, forward |
| `REDACT` | Remove PII, then forward |
| `ESCALATE` | Route to human review |

---

## Sector Presets

```bash
# Apply medical preset (HIPAA + EU AI Act Art. 22)
python examples/sectors/medical_demo.py

# Apply financial preset (MiFID II + GDPR Art. 22)
python examples/sectors/financial_demo.py

# Apply HR preset (anti-discrimination, pay transparency)
python examples/sectors/hr_demo.py
```

---

## Testing

```bash
python tests/test_suite.py       # 21 tests — core, rules, stop controller
python tests/test_suite_v2.py    # 70 tests — crypto, webhooks, rate limiter...
```

91 tests, 91 passing.

---

## Documentation

- [API Reference](docs/API_REFERENCE.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)

---

## Regulatory Coverage

| Regulation | Scope |
|---|---|
| EU AI Act Art. 5, 9, 13, 22 | Prohibited practices, conformity, transparency |
| GDPR Art. 22 | Automated decision-making |
| HIPAA | Medical data protection |
| MiFID II | Financial AI governance |
| EU Equal Treatment Directive | Anti-discrimination in HR |
| EU Pay Transparency Directive 2023/970 | Gender pay equity |

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

---

## License

Copyright 2025 DJAM Foundation / IA Commune Algeria

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for the full text.

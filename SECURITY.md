# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 2.x | ✅ Active |
| 1.x | ⚠️ Security fixes only |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities to: **security@earthflow.djam.foundation**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected component and version
- Potential impact assessment

You will receive an acknowledgement within 48 hours.
We target a patch release within 14 days for critical vulnerabilities.

## Security Architecture

- All API keys encrypted at rest with AES-256 (Fernet)
- Prompt content is never stored — only SHA-256 hashes
- HMAC-SHA256 webhook signature verification
- Token bucket rate limiting per tenant
- TLS required in production
- Non-root container execution
- Read-only container filesystem recommended

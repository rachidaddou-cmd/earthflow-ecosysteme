# Contributing to Earthflow Écosystème

Thank you for your interest in contributing. This document covers the process for submitting changes.

## Code of Conduct

Be respectful, constructive, and professional. We welcome contributors from all backgrounds.

## How to Contribute

### Reporting bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include reproduction steps, environment details, and logs. Security vulnerabilities must be reported privately — see [SECURITY.md](SECURITY.md).

### Proposing features

Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md). Describe the problem, your proposed solution, and any regulatory relevance.

### Submitting a pull request

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. Make your changes. Follow the coding standards below.

3. Add or update tests. All PRs must keep the test suite green:
   ```bash
   python tests/test_suite.py
   python tests/test_suite_v2.py
   ```

4. Add the Apache 2.0 header to any new source file:
   ```python
   # Copyright 2025 DJAM Foundation / IA Commune Algeria
   #
   # Licensed under the Apache License, Version 2.0 (the "License");
   # you may not use this file except in compliance with the License.
   # You may obtain a copy of the License at
   #
   #     http://www.apache.org/licenses/LICENSE-2.0
   ```

5. Open a pull request against `main` with a clear description of what changes and why.

## Coding Standards

- Python 3.10+ compatible code
- Type hints on all public functions
- Docstrings on all public classes and methods
- No `print()` in library code — use the audit log or raise exceptions
- Thread safety for any shared state
- No raw prompt storage — hash with SHA-256

## Commit Messages

```
feat: add threshold operator to rules engine
fix: correct token bucket refill on reset
docs: update deployment guide for Kubernetes 1.29
test: add coverage for multitenant key revocation
```

## Testing Requirements

- New features must include tests
- Bug fixes must include a regression test
- All 91 existing tests must continue to pass
- Tests must be deterministic (no sleep-based timing unless unavoidable)

## Licensing

By submitting a contribution, you agree that your contribution is licensed under the Apache License, Version 2.0, consistent with the project license.

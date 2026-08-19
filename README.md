# 02 — JWT Security Audit Tool (Python, zero dependencies)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)  
[![PyPI](https://img.shields.io/badge/PyPI-available-lightgrey)](#)  
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)](#)  

## Overview

A small, dependency-free Python tool to audit JSON Web Tokens (JWTs) for common misconfigurations and weaknesses. Designed to run in constrained environments (CI pipelines, restricted hosts) and provide a CI-friendly exit code for gating.

This README was upgraded to a full professional template automatically. See CHANGELOG below for details.

---

## Quick links
- Repository: https://github.com/cy1ingachref/02-jwt-audit-tool
- PyPI packaging: pyproject.toml included

## Features
- Detects `alg: none` unsigned tokens
- Identifies weak HMAC secrets (wordlist-based guessing + heuristics)
- Detects missing or empty signatures
- Checks token exp/nbf claims for expired or never-expiring tokens
- Reports algorithm confusion risks (HS* vs RS*/ES*)

## Badges
- PyPI badge: placeholder (publish to enable)
- CI badge: GitHub Actions (placeholder)

## Requirements
- Python 3.7+

## Install
Install locally or in a virtualenv:

```bash
pip install .
# or run without install:
python jwt_audit.py --self-test
```

## Usage examples
Audit a file containing tokens (one per line):

```bash
jwt-audit sample_tokens.txt
# or
python jwt_audit.py --file sample_tokens.txt
```

Audit a single pasted token:

```bash
python jwt_audit.py "<paste.jwt.token>"
```

CI-friendly behavior: exit code 1 for any HIGH finding, 0 otherwise.

## Configuration
- `wordlists/` — optional custom wordlists for weak-secret guessing
- `--threshold` — set severity threshold for failing the CI gate

## Development & Testing
Run the test suite (stdlib unittest):

```bash
python -m unittest discover -v
```

Linting and style: repo uses stdlib only; consider adding a formatter if preferred.

## Contributing
1. Fork the repo and create a branch from `main`.
2. Run tests locally and ensure all pass.
3. Open a PR with a clear description of the change.

See CONTRIBUTING.md for details (auto-generated placeholder).

## License
MIT License — see LICENSE file.

## Maintainer
- Achref Ferjani — https://github.com/cy1ingachref

## CHANGELOG
- 2026-08-19: README upgraded to full professional template by automated process.

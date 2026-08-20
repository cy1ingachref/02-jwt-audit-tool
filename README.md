# 02 — JWT Security Audit Tool (Python, zero dependencies)

A compact, dependency-free JWT auditing utility written for portability and CI integration. This tool checks tokens for common weaknesses (unsigned tokens, weak HMAC secrets, missing signatures, expiry issues, and algorithm confusion) and is designed to run anywhere Python 3.7+ is available.

Why this project matters

- Practical security tooling you can run locally or in CI; high recruiter value for building maintainable security automation.
- No third-party dependencies — minimal supply-chain risk and easy deployment in constrained environments.
- Ships with tests and examples to demonstrate findings and integration into CI gates.

Features

- Detects `alg=none` (unsigned) tokens
- Checks for weak HMAC secrets against built-in/custom wordlists
- Identifies empty or missing signatures
- Flags expiry/nbf hygiene issues
- Surfaces algorithm-confusion risks (when asymmetric keys may be accepted where HMAC is used)

Install & run

pip install .            # installs the `jwt-audit` console script

# or run directly without installation
python jwt_audit.py --self-test            # runs the test suite
python make_sample_tokens.py               # generate demo tokens
python jwt_audit.py --file sample_weak.txt # audit a token file
python jwt_audit.py "<paste.a.jwt.here>"   # audit a single token

Exit codes

- Exit 1: any HIGH finding (suitable for CI gating)
- Exit 0: no HIGH findings

Files

- `jwt_audit.py` — the audit tool
- `make_sample_tokens.py` — demo token generator
- `tests/test_jwt_audit.py` — unit tests (stdlib unittest)
- `pyproject.toml` — packaging configuration
- `GUIDE.md` — code walkthrough and detection rationale

Cross-project integration

This tool is wired into the 01-devsecops-pipeline repository as a CI gate: the pipeline checks out this repo, generates a weak sample token, and fails the build if a HIGH weak-secret finding is not detected. This demonstrates how tooling and CI combine to enforce security automatically.

# 02 — JWT Security Audit Tool (Python, zero dependencies)

**Hireability:** A maintained, tested, documented security tool you wrote and
can ship to PyPI is worth far more than a CTF writeup. It proves you can both
*find* the bug class you discovered at E-Tafakna **and** *build the tooling* to
detect it automatically.

**The story:** At E-Tafakna you found a no-password JWT mint (server compared
tokens by string equality, used a guessable HMAC secret). This tool automates
detection of that exact class plus the standard JWT weaknesses — with NO
external libraries, so it runs anywhere Python 3.7+ exists (great for client
environments and CI).

## What it detects
- `alg = none` — unsigned/forgeable tokens
- Weak HMAC secret — HS256/384/512 signed with a guessable secret (built-in + custom wordlist)
- Empty / missing signature
- Expired or never-expiring tokens (exp/nbf hygiene)
- Algorithm-confusion surface (RS*/ES* used where HS* might be accepted)

## Install & run
```
pip install .            # installs the 'jwt-audit' console script
# or just run the file directly (no install needed):
python jwt_audit.py --self-test            # runs the test suite
python make_sample_tokens.py               # generate safe demo tokens
python jwt_audit.py --file sample_weak.txt # audit a token file
python jwt_audit.py "<paste.a.jwt.here>"   # audit one token
```
Exit code is `1` if any HIGH finding (CI-friendly), `0` otherwise.

## Why zero dependencies?
Recruiters and clients both love "it just runs." Using only the standard
library (`hmac`, `base64`, `json`, `argparse`, `unittest`) means no supply-chain
risk and no install friction — you can drop it into any restricted environment.

## Files
- `jwt_audit.py` — the tool
- `tests/test_jwt_audit.py` — unit tests (stdlib)
- `make_sample_tokens.py` — generates safe demo tokens
- `pyproject.toml` — packaging for PyPI
- `GUIDE.md` — step-by-step explanation of every function

See `GUIDE.md` for the full code-by-code walkthrough.

## Cross-project: used as a CI gate
This tool is wired into the **01-devsecops-pipeline** repo's GitHub Actions
workflow as a real gate: on every push to that repo, Actions checks out this
tool, generates a weak sample token, and fails the build if the HIGH
weak-secret finding is NOT caught. That proves the two portfolio projects work
together — the DevSecOps pipeline actively exercises the security tooling.

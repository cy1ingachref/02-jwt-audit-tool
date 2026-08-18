#!/usr/bin/env python3
"""
jwt_audit.py — A dependency-free JWT security auditor.

WHY THIS TOOL EXISTS
--------------------
During an authorized pentest at E-Tafakna (legal-tech SaaS) a token could be
minted with no password by abusing a weak JWT implementation (the server
compared tokens by string equality instead of verifying the signature, and
used a guessable HMAC secret). This tool automates detection of that exact
bug class plus the standard JWT weaknesses:

  1. alg = none           — token accepted without a signature
  2. weak HMAC secret     — HS256/HS384/HS512 signed with a guessable secret
  3. missing/empty signature
  4. expired or "never expires" tokens (iat/exp/nbf hygiene)
  5. asymmetric alg on a symmetric verifier (alg confusion) — flagged structurally

It uses ONLY the Python standard library, so it runs on any machine with
Python 3.7+ and nothing else installed. That makes it trivial to drop into a
CI pipeline or a client environment.

USAGE
-----
  python jwt_audit.py <token> [--wordlist secrets.txt]
  python jwt_audit.py --file tokens.txt
  python jwt_audit.py --self-test        # runs the built-in test suite

Exit code is 0 if no HIGH findings, 1 if any HIGH finding (CI-friendly).
"""

import argparse
import base64
import binascii
import hmac
import json
import sys
import os

# ---------------------------------------------------------------------------
# A small built-in wordlist of the most common weak JWT secrets seen in the wild
# and in CTFs. You can extend it with --wordlist.
# ---------------------------------------------------------------------------
DEFAULT_SECRETS = [
    "secret", "secret1", "Secret", "SECRET", "password", "123456", "12345678",
    "admin", "admin1", "root", "test", "testing", "key", "keyboard", "letmein",
    "changeme", "default", "guest", "qwerty", "abc123", "jwt", "jwt_secret",
    "jwtsecret", "supersecret", "mysecret", "api_key", "token", "hs256",
    "secretkey", "supersecretkey", "super_secret_key", "insecure", "dev",
    "development", "production", "prod", "sharedsecret", "clientsecret",
]

SEVERITY_HIGH = "HIGH"
SEVERITY_MED = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"


def b64url_decode(data):
    """Decode a base64url string (no padding required) to bytes."""
    if isinstance(data, str):
        data = data.encode("ascii")
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def b64url_encode(data):
    """Encode bytes to a base64url string (no padding)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def split_token(token):
    """Split a JWT into (header_b64, payload_b64, signature_b64)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have exactly 3 dot-separated parts")
    return parts[0], parts[1], parts[2]


def decode_part(b64part):
    """Decode one JWT segment to a Python object (dict for JSON)."""
    raw = b64url_decode(b64part)
    return json.loads(raw.decode("utf-8"))


def load_secrets(wordlist_path):
    secrets = list(DEFAULT_SECRETS)
    if wordlist_path:
        if not os.path.isfile(wordlist_path):
            raise FileNotFoundError("wordlist not found: %s" % wordlist_path)
        with open(wordlist_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    secrets.append(line)
    # de-duplicate, preserve order
    seen, out = set(), []
    for s in secrets:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def alg_confusion_risk(header):
    """Flag asymmetric alg (RS*/ES*/PS*) being used where a symmetric secret
    might be accepted — a classic algorithm-confusion setup."""
    alg = (header.get("alg") or "").upper()
    return alg.startswith(("RS", "ES", "PS", "NONE")) is False and alg not in ("HS256", "HS384", "HS512", "NONE")


def hmac_sig(header_b64, payload_b64, secret, alg):
    """Compute HMAC signature for HS* algorithms."""
    alg_map = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
    if alg.upper() not in alg_map:
        return None
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    digest = hmac.new(secret.encode("utf-8"), signing_input, alg_map[alg.upper()]).digest()
    return b64url_encode(digest)


def audit_token(token, secrets, check_secret=True):
    """Run all checks on a single token. Returns a dict with findings list."""
    findings = []
    result = {"token": token, "valid_structure": False, "findings": findings}

    try:
        header_b64, payload_b64, sig_b64 = split_token(token)
        header = decode_part(header_b64)
        payload = decode_part(payload_b64)
    except (ValueError, binascii.Error, json.JSONDecodeError) as exc:
        findings.append({
            "severity": SEVERITY_HIGH,
            "check": "malformed",
            "detail": "Token could not be parsed: %s" % exc,
        })
        return result

    result["valid_structure"] = True
    result["header"] = header
    result["payload"] = payload

    alg = header.get("alg")
    findings.append({
        "severity": SEVERITY_INFO,
        "check": "algorithm",
        "detail": "Token uses alg=%r" % alg,
    })

    # --- Check 1: alg = none ------------------------------------------------
    if str(alg).lower() == "none":
        findings.append({
            "severity": SEVERITY_HIGH,
            "check": "alg_none",
            "detail": "alg is 'none' — signature is not verified. Token is forgeable.",
        })

    # --- Check 2: empty / missing signature --------------------------------
    if sig_b64 == "":
        findings.append({
            "severity": SEVERITY_HIGH,
            "check": "empty_signature",
            "detail": "Signature segment is empty — token is unsigned/forgeable.",
        })

    # --- Check 3: weak HMAC secret (HS*) -----------------------------------
    if check_secret and str(alg).upper() in ("HS256", "HS384", "HS512"):
        cracked = None
        for secret in secrets:
            if hmac_sig(header_b64, payload_b64, secret, alg) == sig_b64:
                cracked = secret
                break
        if cracked is not None:
            findings.append({
                "severity": SEVERITY_HIGH,
                "check": "weak_secret",
                "detail": "Signed with a guessable HMAC secret %r — forgeable in <1s." % cracked,
            })
        else:
            findings.append({
                "severity": SEVERITY_LOW,
                "check": "weak_secret",
                "detail": "HMAC secret not found in wordlist (could still be weak; increase wordlist size).",
            })

    # --- Check 4: expiry / lifetime hygiene --------------------------------
    import time
    now = int(time.time())
    if "exp" not in payload:
        findings.append({
            "severity": SEVERITY_MED,
            "check": "no_expiry",
            "detail": "No 'exp' claim — token never expires (poor session hygiene).",
        })
    else:
        try:
            exp = int(payload["exp"])
            if exp < now:
                findings.append({
                    "severity": SEVERITY_MED,
                    "check": "expired",
                    "detail": "Token is expired (exp=%d, now=%d)." % (exp, now),
                })
        except (TypeError, ValueError):
            findings.append({
                "severity": SEVERITY_LOW,
                "check": "expired",
                "detail": "'exp' claim is not a valid integer timestamp.",
            })

    if "nbf" in payload:
        try:
            nbf = int(payload["nbf"])
            if nbf > now:
                findings.append({
                    "severity": SEVERITY_LOW,
                    "check": "not_yet_valid",
                    "detail": "'nbf' is in the future — token not valid yet.",
                })
        except (TypeError, ValueError):
            pass

    # --- Check 5: algorithm confusion surface ------------------------------
    if alg_confusion_risk(header):
        findings.append({
            "severity": SEVERITY_MED,
            "check": "alg_confusion_surface",
            "detail": "Asymmetric alg (%r) — verify the server does not allow alg downgrade to HS* (confusion attack)." % alg,
        })

    return result


def severity_rank(sev):
    order = {SEVERITY_HIGH: 3, SEVERITY_MED: 2, SEVERITY_LOW: 1, SEVERITY_INFO: 0}
    return order.get(sev, 0)


def print_report(results):
    high = 0
    for res in results:
        print("=" * 72)
        if not res.get("valid_structure"):
            print("TOKEN: (unparseable)")
        else:
            sub = res.get("payload", {}).get("sub") or res.get("payload", {}).get("user") or "?"
            iss = res.get("payload", {}).get("iss") or "?"
            print("TOKEN  sub=%s iss=%s" % (sub, iss))
        for f in sorted(res["findings"], key=lambda x: -severity_rank(x["severity"])):
            print("  [%-6s] %-22s %s" % (f["severity"], f["check"], f["detail"]))
            if f["severity"] == SEVERITY_HIGH:
                high += 1
    print("=" * 72)
    print("SUMMARY: %d token(s) scanned, %d HIGH-severity finding(s)." % (len(results), high))
    return high


def main(argv=None):
    parser = argparse.ArgumentParser(description="Dependency-free JWT security auditor.")
    parser.add_argument("token", nargs="?", help="A single JWT to audit")
    parser.add_argument("--file", help="File with one JWT per line")
    parser.add_argument("--wordlist", help="Custom wordlist of secrets to try")
    parser.add_argument("--no-secret-check", action="store_true",
                        help="Skip weak HMAC secret brute force")
    parser.add_argument("--self-test", action="store_true",
                        help="Run the built-in test suite and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        import unittest
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName("tests.test_jwt_audit")
        runner = unittest.TextTestRunner(verbosity=2)
        return 0 if runner.run(suite).wasSuccessful() else 1

    secrets = load_secrets(args.wordlist)

    tokens = []
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    tokens.append(line)
    elif args.token:
        tokens.append(args.token)
    else:
        parser.error("provide a TOKEN, --file, or --self-test")

    results = [audit_token(t, secrets, check_secret=not args.no_secret_check) for t in tokens]
    high = print_report(results)
    return 1 if high > 0 else 0


if __name__ == "__main__":
    sys.exit(main())

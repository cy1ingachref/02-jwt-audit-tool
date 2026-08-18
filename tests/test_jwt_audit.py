#!/usr/bin/env python3
"""
tests/test_jwt_audit.py — Unit tests for jwt_audit.py (stdlib only).

Run with:  python jwt_audit.py --self-test
Or:        python -m unittest tests.test_jwt_audit -v
"""

import base64
import hashlib
import hmac
import json
import os
import time
import unittest

# Import the module under test without assuming an installed package.
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "..", "jwt_audit.py")
spec = importlib.util.spec_from_file_location("jwt_audit", MODULE_PATH)
jwt_audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jwt_audit)


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make(header, payload, secret=None, alg="HS256"):
    h = b64url_encode(json.dumps(header, separators=(",", ":")))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")))
    if alg.lower() == "none" or secret is None:
        sig = ""
    else:
        sig = jwt_audit.hmac_sig(h, p, secret, alg)
    return h + "." + p + "." + sig


class TestJwtAudit(unittest.TestCase):

    def setUp(self):
        self.secrets = ["secret", "password", "admin"]

    def test_malformed_token(self):
        res = jwt_audit.audit_token("not.a.jwt", self.secrets)
        self.assertFalse(res["valid_structure"])
        self.assertTrue(any(f["check"] == "malformed" for f in res["findings"]))

    def test_alg_none_is_high(self):
        tok = make({"alg": "none", "typ": "JWT"}, {"sub": "admin"})
        res = jwt_audit.audit_token(tok, self.secrets, check_secret=False)
        self.assertTrue(res["valid_structure"])
        high = [f for f in res["findings"] if f["severity"] == "HIGH" and f["check"] == "alg_none"]
        self.assertTrue(high, "alg=none must be HIGH")

    def test_weak_secret_detected(self):
        tok = make({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"}, secret="secret")
        res = jwt_audit.audit_token(tok, self.secrets)
        high = [f for f in res["findings"] if f["check"] == "weak_secret" and f["severity"] == "HIGH"]
        self.assertTrue(high, "weak secret 'secret' must be cracked")

    def test_strong_secret_not_flagged_high(self):
        strong = hashlib.sha256(os.urandom(32)).hexdigest()
        tok = make({"alg": "HS256", "typ": "JWT"}, {"sub": "user"}, secret=strong)
        res = jwt_audit.audit_token(tok, self.secrets)
        high = [f for f in res["findings"] if f["check"] == "weak_secret" and f["severity"] == "HIGH"]
        self.assertFalse(high, "strong random secret must not be flagged HIGH")

    def test_no_expiry_is_medium(self):
        tok = make({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"}, secret="secret")
        res = jwt_audit.audit_token(tok, self.secrets)
        med = [f for f in res["findings"] if f["check"] == "no_expiry"]
        self.assertTrue(med, "missing exp must be flagged")

    def test_expired_is_medium(self):
        tok = make({"alg": "HS256", "typ": "JWT"},
                   {"sub": "admin", "exp": int(time.time()) - 100}, secret="secret")
        res = jwt_audit.audit_token(tok, self.secrets)
        med = [f for f in res["findings"] if f["check"] == "expired"]
        self.assertTrue(med, "expired token must be flagged")

    def test_empty_signature_is_high(self):
        tok = make({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"})  # no secret -> empty sig path
        # force empty signature
        parts = tok.split(".")
        tok = parts[0] + "." + parts[1] + "."
        res = jwt_audit.audit_token(tok, self.secrets, check_secret=False)
        high = [f for f in res["findings"] if f["check"] == "empty_signature" and f["severity"] == "HIGH"]
        self.assertTrue(high, "empty signature must be HIGH")

    def test_hmac_sig_matches_known_vector(self):
        # Independent recomputation sanity check.
        h = b64url_encode(json.dumps({"alg": "HS256"}, separators=(",", ":")))
        p = b64url_encode(json.dumps({"sub": "x"}, separators=(",", ":")))
        sig = jwt_audit.hmac_sig(h, p, "secret", "HS256")
        expected_inp = (h + "." + p).encode("ascii")
        expected = base64.urlsafe_b64encode(
            hmac.new(b"secret", expected_inp, "sha256").digest()).rstrip(b"=").decode("ascii")
        self.assertEqual(sig, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
make_sample_tokens.py — Generate sample JWTs for testing the auditor.

These are SAFE, offline, self-contained samples (no real secrets, no network).
They demonstrate each finding class so you can show the tool working:

  sample_none.txt        -> alg=none token (forgeable)
  sample_weak.txt        -> token signed with secret "secret" (weak_secret)
  sample_expired.txt     -> token with an expired 'exp' (expired)
  sample_clean.txt       -> a well-formed token with a strong random secret

Run:  python make_sample_tokens.py
Then:  python jwt_audit.py --file sample_weak.txt
"""

import base64
import hashlib
import hmac
import json
import os
import time


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign(header_b64, payload_b64, secret, alg):
    alg_map = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
    inp = (header_b64 + "." + payload_b64).encode("ascii")
    digest = hmac.new(secret.encode("utf-8"), inp, alg_map[alg]).digest()
    return b64url_encode(digest)


def make(header, payload, secret=None, alg="HS256"):
    h = b64url_encode(json.dumps(header, separators=(",", ":")))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")))
    if alg.lower() == "none":
        sig = ""
    else:
        sig = sign(h, p, secret, alg)
    return h + "." + p + "." + sig


now = int(time.time())

# 1) alg=none
none_tok = make({"alg": "none", "typ": "JWT"}, {"sub": "admin", "iss": "etafakna"}, alg="none")

# 2) weak secret "secret"
weak_tok = make({"alg": "HS256", "typ": "JWT"},
                {"sub": "admin", "iss": "etafakna", "exp": now + 3600},
                secret="secret", alg="HS256")

# 3) expired
exp_tok = make({"alg": "HS256", "typ": "JWT"},
               {"sub": "admin", "iss": "etafakna", "exp": now - 3600},
               secret="strongpass", alg="HS256")

# 4) clean (strong, random-ish secret, not in default wordlist)
strong = hashlib.sha256(os.urandom(32)).hexdigest()
clean_tok = make({"alg": "HS256", "typ": "JWT"},
                 {"sub": "user", "iss": "etafakna", "exp": now + 3600, "nbf": now - 10},
                 secret=strong, alg="HS256")

samples = {
    "sample_none.txt": none_tok,
    "sample_weak.txt": weak_tok,
    "sample_expired.txt": exp_tok,
    "sample_clean.txt": clean_tok,
}

for fname, tok in samples.items():
    with open(os.path.join(os.path.dirname(__file__), fname), "w", encoding="utf-8") as fh:
        fh.write(tok + "\n")
    print("wrote %-22s %s" % (fname, tok[:48] + "..."))

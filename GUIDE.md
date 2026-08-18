# GUIDE — 02 JWT Security Audit Tool (step by step, code by code)

Read top to bottom. Every function in `jwt_audit.py` is explained. The tool is
PURE standard library, so you can run it with `python jwt_audit.py` on any
machine — no `pip install` required.

────────────────────────────────────────────────────────────────────────────
STEP 1 — Why this shape (3 parts, base64url)
────────────────────────────────────────────────────────────────────────────
A JWT looks like:  header.payload.signature
Each part is base64url-encoded JSON (header, payload) + a signature. Two helpers
do the encoding/decoding with the URL-safe alphabet and no padding:

  - b64url_decode(data): adds the missing `=` padding, then base64.urlsafe_b64decode
  - b64url_encode(data): base64.urlsafe_b64encode then strip trailing `=`

base64url is just base64 with `+`→`-`, `/`→`_`, and no padding — required so the
token is safe inside URLs/headers.

────────────────────────────────────────────────────────────────────────────
STEP 2 — split_token() and decode_part()
────────────────────────────────────────────────────────────────────────────
  split_token(token)  -> splits on "." and enforces exactly 3 parts. If not 3,
                          raises ValueError (a malformed token is itself a finding).
  decode_part(b64)    -> base64url-decodes then json.loads. This gives you the
                          header dict (alg, typ) and payload dict (sub, exp, ...).

────────────────────────────────────────────────────────────────────────────
STEP 3 — hmac_sig() — recomputing the signature
────────────────────────────────────────────────────────────────────────────
To test if a token used a weak secret, we RECOMPUTE the HMAC signature for each
candidate secret and compare it to the token's signature:

  signing_input = header_b64 + "." + payload_b64
  digest        = hmac.new(secret, signing_input, sha256/384/512).digest()
  sig           = b64url_encode(digest)

If `hmac_sig(...) == token.signature`, we found the secret. This is exactly how
attackers (and this tool) "crack" a JWT — it's offline brute force, no server
contact, which is why a strong, high-entropy secret is mandatory.

────────────────────────────────────────────────────────────────────────────
STEP 4 — audit_token() — the checks
────────────────────────────────────────────────────────────────────────────
Runs all findings on one token and returns a dict:
  { token, valid_structure, header, payload, findings:[...] }

Checks, in order:
  1) alg = none      -> HIGH. Server would skip signature verification.
  2) empty signature -> HIGH. Unsigned token.
  3) weak HMAC secret-> if alg is HS*, brute force the wordlist. Match = HIGH.
  4) expiry hygiene  -> no 'exp' = MEDIUM; expired 'exp' = MEDIUM; bad 'nbf' = LOW.
  5) alg confusion   -> asymmetric alg flagged MEDIUM (verify server can't be
                        downgraded to HS*).

Each finding is a dict {severity, check, detail}. Severity ranking
(HIGH=3, MED=2, LOW=1, INFO=0) is used to sort the report and to set the exit
code (any HIGH -> exit 1).

────────────────────────────────────────────────────────────────────────────
STEP 5 — main() / CLI
────────────────────────────────────────────────────────────────────────────
argparse supports: a single TOKEN, --file (one token per line), --wordlist
(custom secrets), --no-secret-check (skip brute force), --self-test (run tests).

  - load_secrets() merges the built-in DEFAULT_SECRETS with your wordlist, deduped.
  - print_report() prints each token's findings sorted by severity and a summary
    counting HIGH findings.
  - Returns 0 normally, 1 if any HIGH finding — so you can gate CI:
        python jwt_audit.py --file tokens.txt || echo "WEAK TOKENS FOUND"

────────────────────────────────────────────────────────────────────────────
STEP 6 — tests/test_jwt_audit.py
────────────────────────────────────────────────────────────────────────────
Pure stdlib unittest. It imports jwt_audit.py directly via importlib (no install
needed) and asserts:
  - malformed token detected
  - alg=none -> HIGH
  - weak secret "secret" cracked -> HIGH
  - strong random secret NOT flagged HIGH
  - missing exp -> flagged
  - expired token -> flagged
  - empty signature -> HIGH
  - hmac_sig matches an independent recomputation (correctness)

Run it:  python jwt_audit.py --self-test
        (or) python -m unittest tests.test_jwt_audit -v

────────────────────────────────────────────────────────────────────────────
STEP 7 — make_sample_tokens.py (safe demo data)
────────────────────────────────────────────────────────────────────────────
Generates 4 offline sample tokens so you can SHOW the tool working without any
real secrets:
  sample_none.txt      alg=none
  sample_weak.txt      signed with "secret" (weak)
  sample_expired.txt   exp in the past
  sample_clean.txt     strong random secret, valid claims

Run: python make_sample_tokens.py  then  python jwt_audit.py --file sample_weak.txt

────────────────────────────────────────────────────────────────────────────
STEP 8 — packaging for PyPI (pyproject.toml)
────────────────────────────────────────────────────────────────────────────
`pip install .` installs a `jwt-audit` console command (entry point ->
jwt_audit:main). To publish: bump version, then `python -m build` and
`twine upload dist/*`. (You'll need to `pip install build twine` and a PyPI
account — optional, but a published tool is a huge CV boost.)

────────────────────────────────────────────────────────────────────────────
STEP 9 — CV / LinkedIn line
────────────────────────────────────────────────────────────────────────────
"Authored jwt-audit: a dependency-free JWT security scanner (alg=none, weak
HMAC secret brute force, expiry hygiene) with a stdlib test suite — built from
a real finding during an authorized pentest and publishable to PyPI."

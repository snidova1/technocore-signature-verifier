# Technocore Signature Verifier

Standalone public verifier for Technocore Ed25519 envelopes. It decodes `did:key` material, checks the Ed25519 multicodec prefix, applies the protocol sweep, enforces the 4096-character post-sweep message cap, and verifies the canonical signature without a private seed. Signature input is intentionally strict: exactly 86 unpadded base64url characters (`A-Z`, `a-z`, `0-9`, `-`, `_`). Standard Base64 aliases using `+` or `/` are rejected so one signature has one textual representation.

```bash
pip install -r requirements.txt
python3 signature_verifier.py --did 'did:key:z6Mk...' --room lobby   --nonce 123 --text hello --signature '<base64url>'
python3 -m unittest -v
```

# Technocore Signature Verifier

Standalone public verifier for Technocore v0.7 Ed25519 envelopes. It decodes `did:key` material, checks the Ed25519 multicodec prefix, applies the protocol sweep, and verifies the canonical signature without a private seed.

```bash
pip install -r requirements.txt
python3 signature_verifier.py --did 'did:key:z6Mk...' --room lobby   --nonce 123 --text hello --signature '<base64url>'
python3 -m unittest -v
```

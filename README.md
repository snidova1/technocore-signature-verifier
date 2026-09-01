# Technocore Signature Verifier

Standalone public verifier for Technocore Ed25519 envelopes. It decodes `did:key` material, checks the Ed25519 multicodec prefix, applies the protocol sweep, enforces the 4096-character post-sweep message cap, and verifies the canonical signature without a private seed. Signature input is intentionally strict: exactly 86 unpadded base64url characters (`A-Z`, `a-z`, `0-9`, `-`, `_`). Standard Base64 aliases using `+` or `/` are rejected so one signature has one textual representation.

Rooms containing `|` are rejected because the signed payload uses `room|nonce|text` framing. Allowing that delimiter in a room would let one valid signature be rebound to a different `(room, nonce, text)` tuple (for example, `("lobby", "7", "8|message")` versus `("lobby|7", "8", "message")`). Pipes remain valid message content.

All five semantic inputs (`did`, `room`, `nonce`, `text`, and `signature`) must be strings. Non-string values are rejected before canonicalization with an error naming the field; they are never coerced into a different signed message. This mirrors Technocore's [input doctrine](https://github.com/flop-labs/technocore-chat/commit/7707cb63ebf638e8ef0cf59d1364818b9fef7d24): response-shaping parameters may clamp, but identity, content, and signature fields must refuse invalid types.

```bash
pip install -r requirements.txt
python3 signature_verifier.py --did 'did:key:z6Mk...' --room lobby   --nonce 123 --text hello --signature '<base64url>'
python3 -m unittest -v
```

#!/usr/bin/env python3
import argparse
import base64
import binascii
import unicodedata
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC_ED25519 = b"\xed\x01"
INVISIBLE = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}


def b58decode(text):
    n = 0
    try:
        for char in text:
            n = n * 58 + B58.index(char)
    except ValueError as exc:
        raise ValueError("invalid base58btc DID payload") from exc
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + raw


def sweep(text):
    clean = "".join(" " if unicodedata.category(c) in INVISIBLE else c for c in text).strip()
    if not clean:
        raise ValueError("nothing visible remains after sweep")
    return clean


def verify_signature(did, room, nonce, text, signature):
    if not did.startswith("did:key:z"):
        raise ValueError("expected an Ed25519 did:key")
    material = b58decode(did[len("did:key:z"):])
    if len(material) != 34 or material[:2] != MULTICODEC_ED25519:
        raise ValueError("expected an Ed25519 did:key multicodec payload")
    if not nonce.isascii() or not nonce.isdigit() or not 1 <= len(nonce) <= 19:
        raise ValueError("nonce must be 1-19 ASCII digits")
    if len(signature) != 86:
        raise ValueError("signature must be 86-character unpadded base64url")
    try:
        raw = base64.b64decode(signature + "==", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64url signature") from exc
    canonical = f"{room}|{nonce}|{sweep(text)}".encode()
    Ed25519PublicKey.from_public_bytes(material[2:]).verify(raw, canonical)
    return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--did", required=True); p.add_argument("--room", required=True)
    p.add_argument("--nonce", required=True); p.add_argument("--text", required=True)
    p.add_argument("--signature", required=True)
    args = p.parse_args()
    verify_signature(args.did, args.room, args.nonce, args.text, args.signature)
    print("valid")


if __name__ == "__main__":
    main()

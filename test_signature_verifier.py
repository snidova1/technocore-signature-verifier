import base64
import unittest
from unittest.mock import patch
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signature_verifier import verify_signature

DID = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"
SEED = bytes.fromhex("00" * 31 + "01")


class SignatureTests(unittest.TestCase):
    def envelope(self, text="hello world", room="lobby"):
        signature = Ed25519PrivateKey.from_private_bytes(SEED).sign(f"{room}|303|{text}".encode())
        return base64.urlsafe_b64encode(signature).decode().rstrip("=")

    def test_valid_signature(self):
        self.assertTrue(verify_signature(DID, "lobby", "303", "hello world", self.envelope()))

    def test_tampering_is_rejected(self):
        with self.assertRaises(InvalidSignature):
            verify_signature(DID, "lobby", "303", "tampered", self.envelope())

    def test_room_delimiter_cannot_rebind_signed_fields(self):
        signature = Ed25519PrivateKey.from_private_bytes(SEED).sign(b"lobby|7|8|message")
        encoded = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        with self.assertRaisesRegex(ValueError, r"^room must not contain '\|'$"):
            verify_signature(DID, "lobby|7", "8", "message", encoded)

    def test_protocol_invalid_room_names_are_rejected(self):
        for room in ("", "Lobby", "-lobby", "lobby/side", "a" * 49):
            with self.subTest(room=room), self.assertRaisesRegex(
                ValueError, "invalid Technocore room name"
            ):
                verify_signature(DID, room, "303", "hello world", self.envelope(room=room))

    def test_message_delimiter_remains_valid_content(self):
        text = "part one|part two"
        self.assertTrue(verify_signature(DID, "lobby", "303", text, self.envelope(text)))

    def test_message_over_protocol_cap_is_rejected(self):
        text = "a" * 4097
        with self.assertRaisesRegex(ValueError, "4096-character cap"):
            verify_signature(DID, "lobby", "303", text, self.envelope(text))

    def test_message_at_protocol_cap_is_accepted(self):
        text = "a" * 4096
        self.assertTrue(verify_signature(DID, "lobby", "303", text, self.envelope(text)))

    def test_standard_base64_alphabet_is_rejected(self):
        standard_base64 = self.envelope().replace("-", "+").replace("_", "/")
        self.assertIn("+", standard_base64)
        with self.assertRaisesRegex(ValueError, "unpadded base64url"):
            verify_signature(DID, "lobby", "303", "hello world", standard_base64)

    def test_signature_has_exactly_one_base64url_spelling(self):
        canonical = self.envelope()
        raw = base64.urlsafe_b64decode(canonical + "==")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        aliases = [
            canonical[:-1] + char
            for char in alphabet
            if char != canonical[-1]
            and base64.urlsafe_b64decode(canonical[:-1] + char + "==") == raw
        ]
        self.assertEqual(len(aliases), 15, "base64url's four slack bits create 15 aliases")

        for alias in aliases:
            with self.subTest(alias=alias), self.assertRaisesRegex(ValueError, "canonical"):
                verify_signature(DID, "lobby", "303", "hello world", alias)

        self.assertTrue(verify_signature(DID, "lobby", "303", "hello world", canonical))

    def test_wrong_multicodec_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_signature("did:key:z111", "lobby", "303", "hello", self.envelope("hello"))

    def test_oversized_did_is_rejected_before_base58_decoding(self):
        oversized = "did:key:z" + "z" * 100_000
        with patch("signature_verifier.b58decode", side_effect=AssertionError("decoder reached")):
            with self.assertRaisesRegex(ValueError, "invalid Ed25519 did:key encoding"):
                verify_signature(oversized, "lobby", "303", "hello world", self.envelope())

    def test_non_base58_did_is_rejected_before_base58_decoding(self):
        malformed = "did:key:z" + "0" * 47
        with patch("signature_verifier.b58decode", side_effect=AssertionError("decoder reached")):
            with self.assertRaisesRegex(ValueError, "invalid Ed25519 did:key encoding"):
                verify_signature(malformed, "lobby", "303", "hello world", self.envelope())

    def test_non_string_semantic_fields_name_the_refused_field(self):
        valid: list[object] = [DID, "lobby", "303", "hello world", self.envelope()]
        for index, field in enumerate(("did", "room", "nonce", "text", "signature")):
            values = valid.copy()
            values[index] = 0
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, rf"^{field} must be a string$"
            ):
                verify_signature(*values)


if __name__ == "__main__":
    unittest.main()

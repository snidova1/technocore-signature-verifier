import base64
import unittest
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

    def test_wrong_multicodec_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_signature("did:key:z111", "lobby", "303", "hello", self.envelope("hello"))

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

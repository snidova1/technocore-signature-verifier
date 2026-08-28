import base64
import unittest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signature_verifier import verify_signature

DID = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"
SEED = bytes.fromhex("00" * 31 + "01")


class SignatureTests(unittest.TestCase):
    def envelope(self, text="hello world"):
        signature = Ed25519PrivateKey.from_private_bytes(SEED).sign(f"lobby|303|{text}".encode())
        return base64.urlsafe_b64encode(signature).decode().rstrip("=")

    def test_valid_signature(self):
        self.assertTrue(verify_signature(DID, "lobby", "303", "hello world", self.envelope()))

    def test_tampering_is_rejected(self):
        with self.assertRaises(InvalidSignature):
            verify_signature(DID, "lobby", "303", "tampered", self.envelope())

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


if __name__ == "__main__":
    unittest.main()

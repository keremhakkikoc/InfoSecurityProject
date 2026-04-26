import copy
import datetime
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import client


class CryptoPackageTests(unittest.TestCase):
    def setUp(self):
        self.sender_key = client.load_private_key("client1_private.pem")
        self.sender_cert = client.load_certificate("client1_cert.pem")
        self.recipient_key = client.load_private_key("client2_private.pem")
        self.recipient_cert = client.load_certificate("client2_cert.pem")
        self.other_key = client.load_private_key("client1_private.pem")

    def build_signed_package(self):
        plaintext = b"crypto package test content"
        file_key = AESGCM.generate_key(bit_length=256)
        nonce = b"abcdefghijkl"
        ciphertext = AESGCM(file_key).encrypt(nonce, plaintext, None)
        wrapped_key = self.recipient_cert.public_key().encrypt(
            file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        expires_at = (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

        package = {
            "sender": "client1",
            "recipient": "client2",
            "filename": "crypto.txt",
            "expires_at": expires_at,
            "file_hash": client.sha256_b64(plaintext),
            "file_nonce": client.b64e(nonce),
            "ciphertext": client.b64e(ciphertext),
            "ciphertext_hash": client.sha256_b64(ciphertext),
            "wrapped_key": client.b64e(wrapped_key),
        }
        package["signature"] = client.b64e(client.sign_package(package, self.sender_key))
        return package, plaintext

    def test_signature_verifies_for_untampered_package(self):
        package, _ = self.build_signed_package()

        client.verify_package_signature(package, self.sender_cert)

    def test_signature_rejects_tampered_metadata(self):
        package, _ = self.build_signed_package()
        tampered = copy.deepcopy(package)
        tampered["filename"] = "changed-name.txt"

        with self.assertRaises(InvalidSignature):
            client.verify_package_signature(tampered, self.sender_cert)

    def test_signature_rejects_tampered_wrapped_key(self):
        package, _ = self.build_signed_package()
        tampered = copy.deepcopy(package)
        tampered["wrapped_key"] = client.b64e(b"not the original wrapped key")

        with self.assertRaises(InvalidSignature):
            client.verify_package_signature(tampered, self.sender_cert)

    def test_only_recipient_private_key_can_unwrap_file_key(self):
        package, plaintext = self.build_signed_package()

        unwrapped_key = self.recipient_key.decrypt(
            client.b64d(package["wrapped_key"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        decrypted = AESGCM(unwrapped_key).decrypt(
            client.b64d(package["file_nonce"]),
            client.b64d(package["ciphertext"]),
            None,
        )
        self.assertEqual(decrypted, plaintext)

        with self.assertRaises(Exception):
            self.other_key.decrypt(
                client.b64d(package["wrapped_key"]),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )


if __name__ == "__main__":
    unittest.main()

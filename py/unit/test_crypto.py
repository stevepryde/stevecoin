"""Test crypto functions."""

import binascii
import os
import sys
import unittest

sys.path.append('..')  # noqa

# pylint: disable=C0413
from lib.crypto import (CryptHelper, ECDSAPrivateKey, ECDSAPublicKey, Hasher)


class TestCrypto(unittest.TestCase):
    """Test crypto stuff."""

    def verify_roundtrip(self, data):
        """Verify the crypto round-trip using specified data."""
        k, d = CryptHelper.encrypt_json(data)
        value = d.decrypt_json(k)
        self.assertEqual(value, data,
                         "decrypted data should match original")
        return

    def remove_if_exists(self, fn):
        """Delete file if it exists."""
        if os.path.exists(fn):
            os.remove(fn)
        return

    def test_roundtrip(self):
        """Test that AES can round-trip ok."""
        self.verify_roundtrip("The cat sat on the mat")
        self.verify_roundtrip({'key': 'value'})
        self.verify_roundtrip(["hello", "one", "two", "three"])
        return

    def test_ecdsa_sig(self):
        """Test signing of messages."""
        # Generate sig.
        msg = "The cat sat on the mat"
        h = Hasher(msg)
        key = ECDSAPrivateKey.generate()
        sig = h.sign(key)

        # Verify.
        pubkey = key.publickey
        h.verify_signature(sig, pubkey)
        return

    def test_ecdsa_sig_save_load(self):
        """Test signing of messages including saving to a file."""
        # Generate sig.
        msg = "The cat sat on the mat"
        h = Hasher(msg)
        key = ECDSAPrivateKey.generate()
        sig = h.sign(key)

        # Save to a file.
        password = "passphrase"
        fnbase = "keys"
        self.remove_if_exists(fnbase + "_private.pem")
        self.remove_if_exists(fnbase + "_public.pem")
        fnpriv, _ = key.write_key_pair(fnbase, password)

        # Load from file and verify.
        key2 = ECDSAPrivateKey.from_file(fnpriv, password)
        pubkey = key2.publickey
        h.verify_signature(sig, pubkey)
        return

    def test_ecdsa_serialise(self):
        """Test signing of messages including saving to a file."""
        # Generate sig.
        msg = "The cat sat on the mat"
        h = Hasher(msg)
        key = ECDSAPrivateKey.generate()
        sig = h.sign(key)

        # Convert to string.
        pk_str = key.to_string()

        # Convert back to pk and verify.
        key2 = ECDSAPrivateKey.from_string(pk_str)
        pubkey = key2.publickey
        h.verify_signature(sig, pubkey)
        return

    def test_ecdsa_copy_pubkey(self):
        """Test signing of messages including copying the pubkey."""
        # Generate sig.
        msg = "The cat sat on the mat"
        h = Hasher(msg)
        key = ECDSAPrivateKey.generate()
        sig = h.sign(key)

        pubkey1 = key.publickey.as_hash()
        pubkey2 = ECDSAPublicKey(pubkey1)
        h.verify_signature(sig, pubkey2)
        return

    def test_hasher(self):
        """Test the hasher."""
        h = Hasher()
        h.update("hello")
        digest = h.get_hash().digest()
        hexdigest = h.get_hash().to_string()
        self.assertEqual(binascii.hexlify(digest).decode('ascii'), hexdigest,
                         "hexdigest matches digest")
        return

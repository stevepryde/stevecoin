"""Cryptographic helpers."""

import binascii
import json
import re
import secrets
import struct
from typing import Any, IO, List, Optional, Tuple, Union

# pip install base58
import base58

from Cryptodome.Cipher import AES
from Cryptodome.Hash import RIPEMD160, SHA3_256, SHA3_512

# pylint: disable=unused-import
from ecdsa.keys import BadSignatureError
# pylint: enable=unused-import

# pip install ecdsa
from ecdsa import SigningKey, VerifyingKey, SECP256k1


def my_random_bytes(num_bytes: int) -> bytes:
    """Return a random byte string."""
    return secrets.token_bytes(num_bytes)


class KeyValidationError(Exception):
    """Key Verification Failed."""

    pass


class Hash:
    """
    Abstraction for working with hashes.

    It turns out that hashes are a major source of confusion in that they can
    be represented in different ways, and that representation is vitally
    important. For example, do you want a bytes object where each byte
    contains just the binary data (with a length of 64 bytes) or do
    you want a string containing the printable representation of those
    characters, with a length of 128 bytes? And do you want that string
    representation to be an ascii byte string or a unicode string?

    Getting this right is paramount to a working cryptocurrency, and so this
    object is intended to enforce the correct representation where possible.
    """

    def __init__(self, hash_input: Union[str, bytes], bits=512) -> None:
        """
        Create a new Hash object.

        The hash will be auto-inferred based on the type and length of the
        input. The 'bits' parameter is used to determine how many bytes of
        data the hash actually contains. The default is 512, corresponding to
        the SHA3_512 hashes used throughout this project.

        Internally the hash will be stored as bytes containing the binary data,
        since that is what is used in most hash operations.
        """
        num_bytes = int(bits/8)
        self.bits = bits
        self.data = b"0" * num_bytes
        hashlen = len(hash_input)

        # A unicode string is always understood to be a printable
        # representation of a hash. It should only contain ascii characters.
        if isinstance(hash_input, str):
            assert hashlen == (num_bytes * 2), \
                "Unicode hash string length is incorrect. " \
                "Got {}, expected {}".format(hashlen, num_bytes)
            self.data = binascii.unhexlify(hash_input.encode('ascii'))
        elif isinstance(hash_input, bytes):
            if hashlen == (num_bytes * 2):
                self.data = binascii.unhexlify(hash_input)
            elif hashlen == num_bytes:
                self.data = hash_input
            else:
                raise ValueError("Invalid hash length for '{}'. "
                                 "Got {}, expected {}".format(
                                     hash_input, hashlen, num_bytes))
        else:
            raise ValueError("Invalid hash format: {}".format(hash_input))
        return

    def __eq__(self, other: Any) -> bool:
        """Return True if other refers to the same hash."""
        if isinstance(other, Hash):
            return self.data == other.data

        # If other is not a hash, this will assert.
        return self.data == Hash(other, self.bits).data

    def __hash__(self):
        """Get the object hash to allow for comparison in sets."""
        return hash(self.data)

    def serialise(self) -> str:
        """
        Serialise to a unicode string.

        Since hashes are sometimes serialised to JSON, we use unicode strings
        to serialise them.
        """
        return self.to_string()

    def to_string(self) -> str:
        """Get the printable representation of the hash as a unicode string."""
        return binascii.hexlify(self.data).decode('ascii')

    def digest(self) -> bytes:
        """Return the raw binary digest. Use this for all hash operations."""
        return self.data


class Hash512(Hash):
    """Wrapper for a 512-bit hash, as used by Hasher/SHA3_512."""

    def __init__(self, hash_input: Union[str, bytes]) -> None:
        """Create a new Hash512 object."""
        if not hash_input:
            # Convert blank hash to SHA3.
            hash_input = Hasher(b"").get_hash().to_string()

        super().__init__(hash_input, bits=512)
        return

    @staticmethod
    def deserialise(data: str) -> 'Hash512':
        """Deserialise the string into a Hash512 object."""
        return Hash512(data)


class Hash256(Hash):
    """Wrapper for a 256-bit hash, as used by ECDSA keys."""

    def __init__(self, hash_input: Union[str, bytes]) -> None:
        """Create a new Hash256 object."""
        super().__init__(hash_input, bits=256)
        return

    @staticmethod
    def deserialise(data: str) -> 'Hash256':
        """Deserialise the string into a Hash256 object."""
        return Hash256(data)


def basic_hash_check(h: Union[str, Hash]) -> None:
    """Assert that the hash consists of alphanumeric characters only."""
    if isinstance(h, Hash):
        h = h.to_string()
    assert re.search(r'^[a-fA-F0-9]+$', h), "Hash check failed"
    return


class CryptoAddress:
    """
    A specific type used to store the base58 wallet addresses.

    The primary purpose of this class is to differentiate addresses from
    regular hashes, including facilitating type safety checks.
    """

    def __init__(self, address: str) -> None:
        """Create a new CryptoAddress object."""
        self.address = str(address)
        return

    def __eq__(self, other: Any) -> bool:
        """Check for equality."""
        if isinstance(other, CryptoAddress):
            return self.address == other.address

        return self.address == other

    def __hash__(self):
        """Get the object hash to allow for comparison in sets."""
        return hash(self.address)

    def serialise(self) -> str:
        """Serialise the address."""
        return self.address  # It's already a string.

    @staticmethod
    def deserialise(data: str) -> 'CryptoAddress':
        """Deserialise the string into a CryptoAddress object."""
        return CryptoAddress(data)

    def to_string(self) -> str:
        """Return string representation."""
        return self.address


class EncryptedData:
    """Helper for encrypted data."""

    def __init__(self, nonce: bytes, tag: bytes,
                 encrypted_data: bytes) -> None:
        """Create a new EncryptedData object."""
        self.nonce = nonce
        self.tag = tag
        self.encrypted_data = encrypted_data
        return

    def decrypt(self, key: Hash256) -> bytes:
        """Decrypt the data using the specified key."""
        cipher = AES.new(key.digest(), AES.MODE_EAX, self.nonce)
        ciphertext = cipher.decrypt_and_verify(self.encrypted_data, self.tag)
        return ciphertext

    def decrypt_with_passphrase(self, passphrase: str) -> bytes:
        """Decrypt the data using the specified passphrase."""
        key = Hash256(SHA3_256.new(data=passphrase.encode('utf-8')).digest())
        return self.decrypt(key)

    def decrypt_json(self, key: Hash256) -> Any:
        """Decrypt and unpack JSON, returning data structure."""
        json_str = self.decrypt(key)
        return json.loads(json_str)

    def write_to_file(self, filename: str,
                      overwrite_if_exists: bool = False) -> None:
        """Write the encrypted data to a file."""
        mode = "xb"
        if overwrite_if_exists:
            mode = "wb"

        with open(filename, mode) as f:
            self._write_bytes(f, self.nonce)
            self._write_bytes(f, self.tag)
            self._write_bytes(f, self.encrypted_data)
        return

    def _write_bytes(self, f: IO, b: bytes) -> None:
        """Write bytes to a file as length + data."""
        f.write(struct.pack("<Q", len(b)))
        f.write(b)
        return

    @staticmethod
    def read_from_file(filename: str) -> 'EncryptedData':
        """Read encrypted data from a file and return EncryptedData."""
        # Silence pydocstyle D202.

        def _read_bytes(f: IO) -> bytes:
            """Read a byte string from the current file position."""
            size = struct.unpack("<Q", f.read(8))[0]
            return f.read(size)

        with open(filename, "rb") as f:
            nonce = _read_bytes(f)
            tag = _read_bytes(f)
            data = _read_bytes(f)
            return EncryptedData(nonce=nonce, tag=tag, encrypted_data=data)


class CryptHelper:
    """Crypto helper class."""

    def __init__(self):
        """Create a new CryptHelper object (N/A)."""
        assert False, "Use static methods, not new()"
        return

    @staticmethod
    def encrypt(data: bytes) -> Tuple[Hash256, EncryptedData]:
        """Encrypt some data with a randomly generated key."""
        key = Hash256(my_random_bytes(32))
        cipher = AES.new(key.digest(), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return key, EncryptedData(cipher.nonce, tag, ciphertext)

    @staticmethod
    def encrypt_json(data: Any) -> Tuple[Hash256, EncryptedData]:
        """Encrypt some object after first converting to JSON."""
        return CryptHelper.encrypt(json.dumps(data).encode('utf-8'))

    @staticmethod
    def encrypt_with_passphrase(data: bytes, passphrase: str) -> EncryptedData:
        """Encrypt some data with the specified password."""
        key = SHA3_256.new(data=passphrase.encode('utf-8')).digest()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return EncryptedData(cipher.nonce, tag, ciphertext)

    @staticmethod
    def get_hash_of_list(data_list: List[Union[bytes, str]]) -> Hash512:
        """Get the crypto hash for the specified list of items."""
        h = SHA3_512.new()
        for item in data_list:
            if isinstance(item, bytes):
                h.update(item)
            elif isinstance(item, str):
                h.update(item.encode('utf-8'))
            else:
                assert False, \
                    "Item must be bytes or str, but got {!r}".format(item)
        return Hash512(h.digest())


class ECDSAPublicKey:
    """Wrapper around a public ECDSA (verifying) key."""

    def __init__(self, pk: Union[VerifyingKey, bytes, str]) -> None:
        """Create a new ECDSAPublicKey object."""
        assert pk, "No pk specified!"

        if isinstance(pk, Hash512):
            self.key = VerifyingKey.from_string(pk.digest(),
                                                curve=SECP256k1)
        elif isinstance(pk, Hash):
            raise TypeError("Invalid hash type: {}".format(pk.to_string()))
        elif isinstance(pk, (str, bytes)):
            self.key = VerifyingKey.from_string(pk, curve=SECP256k1)
        else:
            self.key = pk
        return

    def as_hash(self) -> Hash512:
        """Get the key as a Hash512 object."""
        return Hash512(self.key.to_string())

    def as_pem(self) -> bytes:
        """Get the public key as a PEM format byte string."""
        return self.key.to_pem()

    def get_address(self) -> CryptoAddress:
        """Get the address corresponding to this public key, as bytes."""
        # NOTE: Use SHA3_256 to produce a different address than bitcoin.
        # If SHA256 is used, a bitcoin address would be produced.
        h = SHA3_256.new(self.key.to_string()).digest()
        r = RIPEMD160.new(h).digest()
        rv = b'\0' + r
        return CryptoAddress(base58.b58encode_check(rv))


class ECDSAPrivateKey:
    """Wrapper around a private ECDSA (signing) key."""

    def __init__(self, pk: Union[SigningKey, bytes, str]) -> None:
        """Create a new ECDSAPublicKey object."""
        assert pk, "No pk specified!"

        if isinstance(pk, (str, bytes)):
            self.key = SigningKey.from_string(pk, curve=SECP256k1)
        else:
            self.key = pk
        return

    @staticmethod
    def generate() -> 'ECDSAPrivateKey':
        """Generate a new key pair."""
        return ECDSAPrivateKey(pk=SigningKey.generate(curve=SECP256k1))

    @staticmethod
    def from_file(filename: str, passphrase: str) -> 'ECDSAPrivateKey':
        """Read from file (as written by write_key_pair)."""
        data = EncryptedData.read_from_file(filename)
        key = binascii.unhexlify(data.decrypt_with_passphrase(passphrase))
        return ECDSAPrivateKey(SigningKey.from_string(key, curve=SECP256k1))

    @property
    def publickey(self) -> 'ECDSAPublicKey':
        """Get the public key."""
        return ECDSAPublicKey(pk=self.key.get_verifying_key())

    @staticmethod
    def from_string(s) -> 'ECDSAPrivateKey':
        """Convert string to ECDSAPrivateKey object."""
        return ECDSAPrivateKey(binascii.unhexlify(s))

    def to_string(self):
        """
        Get the key as a string.

        WARNING: Do not store this to disk or send it over a network
        unencrypted.
        """
        return binascii.hexlify(self.key.to_string()).decode('utf-8')

    def write_key_pair(self, filename_prefix: str, passphrase: str) \
            -> Tuple[str, str]:
        """Write key pair to the specified filename prefix."""
        assert len(passphrase) >= 8, "Passphrase must be at least 8 chars!"

        fname_private = filename_prefix + "_private.pem"
        fname_public = filename_prefix + "_public.pem"

        key = binascii.hexlify(self.key.to_string())
        data = CryptHelper.encrypt_with_passphrase(
            data=key, passphrase=passphrase)
        data.write_to_file(fname_private)

        with open(fname_public, 'xt') as fpub:
            fpub.write(self.publickey.as_pem().decode('utf-8'))
        return fname_private, fname_public


# Type def for Hasher.update().
Hashable = Union[bytes, str, Hash]
HashableList = Union[Hashable, List[Hashable]]


class Hasher:
    """Hasher object to work with hashes."""

    def __init__(self, message_or_list: Optional[HashableList] = None) -> None:
        """Create a new Hasher object."""
        self.h = SHA3_512.new()
        if message_or_list:
            self.update(message_or_list)
        return

    def update(self, message_or_list: HashableList) -> 'Hasher':
        """Add message to hash."""
        if not isinstance(message_or_list, list):
            message_or_list = [message_or_list]  # type: ignore

        for msg in message_or_list:
            if isinstance(msg, Hash):
                self.h.update(msg.digest())
            elif isinstance(msg, bytes):
                self.h.update(msg)
            elif isinstance(msg, str):
                self.h.update(msg.encode('utf-8'))
            else:
                assert False, \
                    "Item must be bytes or str, but got {!r}".format(msg)
        return self  # Allow chaining.

    def get_hash(self) -> Hash512:
        """Get the resulting hash as a Hash512 object."""
        return Hash512(self.h.digest())

    def base58(self) -> bytes:
        """Get the base58 encoded bytes for this hash."""
        return base58.b58encode(self.h.digest())

    def sign(self, private_key: ECDSAPrivateKey) -> Hash512:
        """Sign the hash with the private key."""
        assert isinstance(private_key, ECDSAPrivateKey), \
            "Signing a hash requires a private key of type ECDSAPrivateKey"

        sig_raw = private_key.key.sign(self.h.digest())
        return Hash512(sig_raw)

    def verify_signature(self, sig: Hash512, public_key: ECDSAPublicKey) \
            -> None:
        """
        Verify that the signature was signed with the private key.

        This also verifies that the signature matches the hashed data.
        """
        try:
            assert isinstance(public_key, ECDSAPublicKey), \
                "Verifying a hash requires a public key of type ECDSAPublicKey"

            assert isinstance(sig, Hash512), "sig must be a Hash256 object"

            if not bool(public_key.key.verify(sig.digest(), self.h.digest())):
                raise KeyValidationError("Signature Verification Failed")
            return
        except AssertionError as exc:
            raise KeyValidationError("Invalid signature") from exc

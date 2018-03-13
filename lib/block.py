"""Data structure for a single block."""

import base64
import datetime
import json
# pylint: disable=unused-import
from typing import Any, Dict, List, Set, TYPE_CHECKING
# pylint: enable=unused-import

# pylint: disable=C0411,R0902
from .crypto import Hash512, Hasher, my_random_bytes
from .errors import (BlockDifficultyError, BlockNotFoundError,
                     BlockValidationError)
from .transaction import Transaction

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from querylayer import QueryLayer
    # pylint: enable=unused-import


BLOCK_CURRENT_VERSION = 1
MAX_TRANSACTIONS_PER_BLOCK = 10
MAX_BLOCKSIZE = 4096
GENESIS_HASH = b"There can be only one"
NONCE_SIZE = 4


class Block:
    """Block class."""

    def __init__(self, index: int, prev_hash: Hash512) -> None:
        """Create a new Block object."""
        self.index = index
        self.version = BLOCK_CURRENT_VERSION

        now = datetime.datetime.now(datetime.timezone.utc)
        self.timestamp = int(now.timestamp())

        self.transactions = []  # type: List[Transaction]
        self.merkle_root = Hash512(b'')  # Root hash of Merkle Tree.

        self.prev_hash = prev_hash
        self.salt = my_random_bytes(NONCE_SIZE)

        self.nonce = my_random_bytes(NONCE_SIZE)
        self.hash = Hash512(b'')
        return

    @staticmethod
    def deserialise(data: str) -> 'Block':
        """Deserialise from bytes to a Block object."""
        d = json.loads(data)
        return Block.deserialise_dict(d)

    @staticmethod
    def deserialise_dict(d: Dict[str, Any]) -> 'Block':
        """Deserialise from dict to a Block object."""
        version = d['version']
        if version == 1:
            b = Block(
                index=d['index'],
                prev_hash=Hash512.deserialise(d['prevhash'])
            )
            b.version = version
            b.timestamp = d['ts']
            b.transactions = [Transaction.deserialise(x)
                              for x in d['transactions']]
            b.merkle_root = Hash512.deserialise(d['merkle'])
            b.nonce = base64.b64decode(d['nonce'])
            b.salt = base64.b64decode(d['salt'])
            b.hash = Hash512.deserialise(d['hash'])
            return b

        raise Exception("Unknown block version: {}".format(version))

    def serialise_dict(self) -> Dict[str, Any]:
        """Serialise this block to a dict."""
        return {
            'version': self.version,
            'index': self.index,
            'ts': self.timestamp,
            'transactions': self.get_serialised_transactions(),
            'merkle': self.merkle_root.serialise(),
            'prevhash': self.prev_hash.serialise(),
            'salt': base64.b64encode(self.salt).decode('utf-8'),
            'nonce': base64.b64encode(self.nonce).decode('utf-8'),
            'hash': self.hash.serialise()
        }

    def serialise(self) -> str:
        """Serialise this block to JSON str."""
        if self.version == 1:
            return json.dumps(self.serialise_dict())

        raise Exception("Unknown block version: {}".format(self.version))

    def get_serialised_transactions(self) -> List[str]:
        """Get serialised transaction data."""
        return [x.serialise() for x in self.transactions]

    def calculate_merkle_root(self) -> Hash512:
        """Calculate the merkle root hash."""
        hashes = [x.txid for x in self.transactions]

        while len(hashes) > 1:
            # If an odd number, repeat the last one.
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])

            hashes_out = []
            for i in range(0, len(hashes), 2):
                h = Hasher([
                    hashes[i],
                    hashes[i+1]
                ]).get_hash()
                hashes_out.append(h)

            hashes = hashes_out
        return hashes[0]

    def calculate_hash(self) -> Hash512:
        """Calculate the hash."""
        return Hasher([
            str(self.version),
            str(self.index),
            str(self.timestamp),
            str(len(self.transactions)),
            self.merkle_root,
            self.prev_hash,
            self.salt,
            self.nonce
        ]).get_hash()

    def calculate_new_hash(self) -> Hash512:
        """Modify the nonce and recalculate the hash."""
        self.nonce = my_random_bytes(NONCE_SIZE)
        return self.calculate_hash()

    def verify_pow(self, pow_difficulty: int) -> None:
        """Verify that this block meets POW criteria."""
        hstr = self.hash.to_string()
        if hstr[:pow_difficulty] != '0' * pow_difficulty:
            raise BlockDifficultyError("Block difficulty too low")
        return

    def ensure_difficulty(self, pow_difficulty: int) -> None:
        """Keep recalculating the hash until difficulty level is met."""
        while True:
            try:
                self.verify_pow(pow_difficulty)
                break
            except BlockDifficultyError:
                self.hash = self.calculate_new_hash()
        return

    def validate(self, q: 'QueryLayer', pow_difficulty: int) -> bool:
        """Validate this block."""
        try:
            self.verify_pow(pow_difficulty)

            if self.index > 0:
                # Ensure transaction inputs are unique for the entire block.
                known_inputs = set()  # type: Set[Hash512]

                for trans in self.transactions:
                    trans.validate(q)

                    # Multiple transactions in the same block, referencing the
                    # same input, are not allowed!
                    trans.check_duplicates(known_inputs)

            assert self.version == 1, \
                "Unknown version {!r}".format(self.version)

            assert len(self.serialise()) <= MAX_BLOCKSIZE, \
                "Block exceeds maximum size of {} bytes".format(MAX_BLOCKSIZE)

            assert len(self.transactions) <= MAX_TRANSACTIONS_PER_BLOCK, \
                "Block contains too many transactions"

            d = datetime.datetime.fromtimestamp(self.timestamp)
            assert d > datetime.datetime(2018, 1, 1), \
                "Block timestamp is too old!"
            assert d < datetime.datetime.now(), \
                "Block timestamp is in the future!"

            assert self.index >= 0 and self.index <= q.get_num_blocks(), \
                "Invalid block index"

            if self.index == 0:
                # Compare genesis block against the blockchain.
                try:
                    genblock = q.get_block(0)
                    assert self.hash == genblock.hash, \
                        "Block hash mismatch"
                except BlockNotFoundError:
                    # Brand new blockchain?
                    assert q.get_num_blocks() == 0, "Block count mismatch"
                    assert self.hash == Hasher(GENESIS_HASH).get_hash(), \
                        "Block hash mismatch"
            else:
                prev_block = q.get_block(self.index - 1)
                assert self.prev_hash == prev_block.hash, \
                    "Previous block hash mismatch"

            assert self.merkle_root == self.calculate_merkle_root(), \
                "Block merkle root hash mismatch"

            assert self.hash == self.calculate_hash(), "Block hash mismatch"

        except (AssertionError, BlockDifficultyError) as exc:
            raise BlockValidationError(
                "Error validating block: {}".format(self.index)) from exc
        return True

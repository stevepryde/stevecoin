"""Database abstraction for the blockchain and related structures on disk."""

import json
import os
import struct
from typing import Dict, List, TYPE_CHECKING

import plyvel

# pylint: disable=C0411
from .block import Block
from .crypto import CryptoAddress, ECDSAPublicKey, Hash512
from .errors import (BlockNotFoundError, BlockValidationError,
                     IndexIntegrityError, TransactionNotFoundError)
from .transaction import Transaction

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from querylayer import QueryLayer
    # pylint: enable=unused-import

BLOCKS_PER_FILE = 10000
WORDSIZE = 8
INITIAL_POW = 2


def packdict(d: Dict) -> bytes:
    """Pack a dictionary into a JSON byte string."""
    return json.dumps(d).encode('utf-8')


def packint(i: int) -> bytes:
    """Pack an int into a byte string."""
    return struct.pack("<Q", i)


def unpackint(b: bytes) -> int:
    """Unpack a bytes string into a single int (only the first is returned)."""
    return struct.unpack("<Q", b)[0]


class BlockDB:
    """Database layer for blockchain."""

    def __init__(self, base_dir: str) -> None:
        """Create a new BlockDB object."""
        self.base_dir = base_dir
        self.indexfile = os.path.join(self.base_dir, "index.db")
        self.db = plyvel.DB(self.indexfile, create_if_missing=True)
        self.num_blocks = self.db.get(b"sc_numblocks") or 0
        self.pow_difficulty = self.db.get(b"sc_pow") or INITIAL_POW
        return

    def consistency_check(self, q: 'QueryLayer') -> None:
        """Perform consistency check between blockchain and index."""
        index = 0
        offset = 0
        lastfn = ''
        try:
            while True:
                fn = self.get_filename_for_block(index)
                if fn != lastfn:
                    offset = 0
                lastfn = fn

                data = self.read_chunk(fn, offset)
                size = len(data)

                try:
                    block_offset = self.get_block_offset(index)
                    assert block_offset == offset, \
                        "Invalid block offset for block {}".format(index)
                except BlockNotFoundError:
                    self.set_block_offset(index, offset)

                index += 1
                offset += WORDSIZE + size  # Account for size header.
        except AssertionError as exc:
            raise IndexIntegrityError("Consistency check failed") from exc
        except (IOError, EOFError):
            pass

        self.num_blocks = index
        self.db.put(b"sc_numblocks", packint(self.num_blocks))

        # Validate all blocks.
        for i in range(self.num_blocks):
            block = self.get_block(i)
            block.validate(q, self.pow_difficulty)
            self.update_transaction_indexes(block)

        if self.num_blocks > 0:
            print("Consistency check passed...")
        return

    def get_filename_for_block(self, block_index: int) -> str:
        """Get the filename corresponding to the specified block."""
        # We split blocks over several files to avoid going over the
        # max file size for the file system.
        file_num = int(block_index / BLOCKS_PER_FILE)
        file_suffix = "{:x}".format(file_num)
        return os.path.join(self.base_dir, "bdata_{}.blk".format(file_suffix))

    def get_key_for_block(self, block_index: int) -> bytes:
        """Get the levelDB key for the specified block."""
        return "block{:09d}".format(block_index).encode('utf-8')

    def get_key_for_transaction(self, txid: Hash512) -> bytes:
        """Get the levelDB key for the specified transaction id."""
        txid_str = txid.to_string()
        return "txid_{}".format(txid_str).encode('utf-8')

    def get_key_for_utxo(self, txid: Hash512, address: CryptoAddress) -> bytes:
        """Get the levelDB key for the specified UTXO entry."""
        txid_str = txid.to_string()
        address_str = address.to_string()

        # Put address first, since there may be multiple transactions
        # that output to that address, and this makes it easier to search
        # by address only.
        return "utxo_{}_{}".format(address_str, txid_str).encode('utf-8')

    def get_utxo_keys_for_address(self, address: CryptoAddress) -> List[bytes]:
        """Get UTXO keys for the specified address."""
        address_str = address.to_string()
        prefix = "utxo_{}_".format(address_str).encode('utf-8')
        keys = []
        for key in self.db.iterator(prefix=prefix, include_key=True,
                                    include_value=False):
            keys.append(key)
        return keys

    def get_txids_for_address(self, address: CryptoAddress) -> List[Hash512]:
        """Get all (unspent) input txids for the specified address."""
        address_str = address.to_string()
        prefix = "utxo_{}_".format(address_str).encode('utf-8')
        keys = self.get_utxo_keys_for_address(address)
        txids = []
        for key in keys:
            assert key.find(prefix) == 0, "UTXO key doesn't match address"
            txid = key.replace(prefix, b'', 1)
            txids.append(Hash512(txid))
        return txids

    def get_block_offset(self, block_index: int) -> int:
        """Get the file offset for the specified block."""
        key = self.get_key_for_block(block_index)
        raw_data = self.db.get(key)
        if raw_data is None:
            raise BlockNotFoundError(
                "Unable to find block {}".format(block_index))
        return unpackint(raw_data)

    def set_block_offset(self, block_index: int, offset: int, wb=None) -> None:
        """Set the block offset for the specified block."""
        if not wb:
            wb = self.db

        key = self.get_key_for_block(block_index)
        wb.put(key, packint(offset))
        return

    def read_chunk(self, blockfile: str, offset: int) -> bytes:
        """Read a chunk from the block data."""
        # The file simply stores size (4 bytes) + data (<size> bytes).
        with open(blockfile, "rb") as f:
            f.seek(offset)
            # Read size as unsigned long long (8 bytes).
            raw_data = f.read(WORDSIZE)
            if not raw_data:
                raise EOFError("Tried to read after EOF")

            size = struct.unpack('<Q', raw_data)[0]
            return f.read(size)

    def write_chunk(self, blockfile: str, data: bytes) -> int:
        """Write a chunk to the end of the block data."""
        offset = None
        with open(blockfile, "ab") as f:
            offset = f.tell()
            # Write size as unsigned long long (8 bytes).
            f.write(struct.pack('<Q', len(data)))
            f.write(data)
        return offset

    def get_block(self, block_index: int) -> Block:
        """Read a block from the block data."""
        offset = self.get_block_offset(block_index)
        blockfile = self.get_filename_for_block(block_index)
        data = self.read_chunk(blockfile, offset)
        return Block.deserialise(data.decode('utf-8'))

    def update_transaction_indexes(self, block: Block) -> None:
        """Update all UTXO indexes and amounts."""
        # Add transaction indexes.
        with self.db.write_batch() as wb:
            for trans in block.transactions:
                txkey = self.get_key_for_transaction(trans.txid)
                wb.put(txkey, packint(block.index))

                # Delete UTXO for inputs.
                for txinput in trans.inputs:
                    addr = ECDSAPublicKey(txinput.pubkey).get_address()
                    utxokey = self.get_key_for_utxo(txinput.txid, addr)
                    wb.delete(utxokey)

                # Add UTXO for outputs.
                for output in trans.outputs:
                    utxokey = self.get_key_for_utxo(trans.txid,
                                                    output.address)
                    wb.put(utxokey, packint(output.amount))
        return

    def write_new_block(self, block: Block, q: 'QueryLayer',
                        genesis: bool = False) -> None:
        """Write a new block to the blockchain."""
        index = self.num_blocks
        assert block.index == index, \
            "New block index does not match blockchain!"

        if not genesis:
            block.validate(q, self.pow_difficulty)

        blockfile = self.get_filename_for_block(index)
        offset = self.write_chunk(blockfile, block.serialise().encode('utf-8'))
        self.set_block_offset(index, offset)
        self.update_transaction_indexes(block)

        self.num_blocks += 1
        self.db.put(b"sc_numblocks", packint(self.num_blocks))
        return

    def get_utxo_amount(self, txid: Hash512, address: CryptoAddress) -> int:
        """Get the amount associated with the specified UTXO."""
        utxokey = self.get_key_for_utxo(txid, address)
        raw_value = self.db.get(utxokey)
        if raw_value is None:
            raise TransactionNotFoundError("UTXO not found")
        return unpackint(raw_value)

    def get_transaction(self, txid: Hash512) -> Transaction:
        """Get the specified transaction from the blockchain."""
        txid_str = txid.to_string()
        txkey = self.get_key_for_transaction(txid)
        raw_value = self.db.get(txkey)
        if raw_value is None:
            raise TransactionNotFoundError(
                "Unable to find transaction {}".format(txid_str))

        block_index = unpackint(raw_value)
        try:
            block = self.get_block(block_index)
            for trans in block.transactions:
                if trans.txid == txid:
                    return trans

            raise TransactionNotFoundError(
                "Unable to find transaction {} in block {}".
                format(txid_str, block_index))
        except (BlockNotFoundError, BlockValidationError) as exc:
            raise TransactionNotFoundError(
                "Unable to find transaction {}".format(txid_str)) from exc

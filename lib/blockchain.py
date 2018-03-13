"""Blockchain in Python."""

import os
import sys


# pylint: disable=C0411
from .block import Block
from .blockdb import BlockDB, packint
from .crypto import Hasher, ECDSAPrivateKey
from .querylayer import QueryLayer
from .transaction import Transaction, TransactionInput, TransactionOutput
from .transdb import TransDB

TOTAL_COINS = 987654321000


class BlockChain:
    """Blockchain object."""

    def __init__(self, base_dir: str) -> None:
        """Create a new BlockChain object."""
        self.base_dir = base_dir
        self.blockdb = BlockDB(base_dir=self.base_dir)
        self.transdb = TransDB(base_dir=self.base_dir)
        self.q = QueryLayer(bdb=self.blockdb, tdb=self.transdb)
        self.blockdb.consistency_check(self.q)
        return

    def create(self, passphrase: str) -> None:
        """Create a new blockchain (must not already exist!)."""
        assert self.blockdb.num_blocks == 0, "Blockchain already exists!"

        print("Creating new blockchain...")
        # Create initial keys.
        pk = ECDSAPrivateKey.generate()
        try:
            key_prefix = os.path.join(self.base_dir, "genesis_key")
            pk.write_key_pair(filename_prefix=key_prefix,
                              passphrase=passphrase)
        except FileExistsError as exc:
            print("Unable to write key file: {}".format(exc))
            print("Blockchain not created.")
            sys.exit(1)

        # Add genesis block manually.
        block = Block(0, Hasher(b"There can be only one").get_hash())
        address = pk.publickey.get_address()
        to = TransactionOutput(address=address, amount=TOTAL_COINS)

        # Fake the UTXO in.
        txid = Hasher(b"Genesis").get_hash()
        utxokey = self.blockdb.get_key_for_utxo(txid, address)
        self.blockdb.db.put(utxokey, packint(TOTAL_COINS))

        # Sign the input.
        output_hash = Hasher([
            to.get_hash()
        ]).get_hash()
        sig = Hasher([
            txid,
            output_hash
        ]).sign(pk)

        ti = TransactionInput(txid=txid, pubkey=pk.publickey.as_hash(),
                              sig=sig)
        t = Transaction(inputs=[ti], outputs=[to])
        t.output_hash = t.calculate_output_hash()
        t.txid = t.calculate_txid()
        t.validate(self.q)

        block.transactions = [t]
        block.merkle_root = block.calculate_merkle_root()
        block.hash = block.calculate_hash()
        print("Mining Genesis Block...")
        block.ensure_difficulty(self.blockdb.pow_difficulty)

        print("Writing Genesis Block...")
        self.blockdb.write_new_block(block, self.q, genesis=True)

        # Force another consistency check to read indexes etc.
        self.blockdb.consistency_check(self.q)
        return

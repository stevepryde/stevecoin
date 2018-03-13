"""Database for the pending transactions pool."""

import os
from typing import Generator

import plyvel

from .crypto import Hash512
from .errors import TransactionNotFoundError
from .transaction import Transaction


class TransDB:
    """Database for pending transactions."""

    def __init__(self, base_dir: str) -> None:
        """Create a new TransDB object."""
        self.base_dir = base_dir
        self.transfile = os.path.join(self.base_dir, "trans.db")
        self.db = plyvel.DB(self.transfile, create_if_missing=True)
        return

    def bump_index(self) -> int:
        """Bump the next transaction index and return the existing one."""
        index = int(self.db.get(b'nextindex', b'0'))
        next_index = index + 1
        self.db.put(b'nextindex', str(next_index).encode('utf-8'))
        return index

    def get_key_for_index(self, index: int) -> bytes:
        """Get the key for the specified index."""
        return "trans_{:09d}".format(index).encode('utf-8')

    def get_key_for_txid(self, txid: Hash512) -> bytes:
        """Get the key for the specified transaction id."""
        txid_str = txid.to_string()
        return "txid_{}".format(txid_str).encode('utf-8')

    def get_key_bumped_index(self) -> bytes:
        """Bump the index and get the key."""
        return self.get_key_for_index(self.bump_index())

    def add_transaction(self, trans: Transaction) -> None:
        """Add the transaction to the pool."""
        data = trans.serialise().encode('utf-8')
        key = self.get_key_bumped_index()
        self.db.put(key, data)

        # Link transaction id to key.
        txkey = self.get_key_for_txid(trans.txid)
        self.db.put(txkey, key)
        return

    def get_transaction(self, txid: Hash512) -> Transaction:
        """Get the specified transaction."""
        txid_str = txid.to_string()
        txkey = self.get_key_for_txid(txid)
        key = self.db.get(txkey)
        if key is None:
            raise TransactionNotFoundError(
                "Unable to find transaction {}".format(txid_str))

        raw_data = self.db.get(key)
        if raw_data is None:
            raise TransactionNotFoundError(
                "Unable to find transaction {}".format(txid_str))

        return Transaction.deserialise(raw_data)

    def delete_transaction(self, txid: Hash512) -> None:
        """Delete the specified transaction from the pending list."""
        txid_str = txid.to_string()
        txkey = self.get_key_for_txid(txid)
        key = self.db.get(txkey)
        if key is None:
            raise TransactionNotFoundError(
                "Unable to find transaction {}".format(txid_str))

        with self.db.write_batch() as wb:
            wb.delete(key)
            wb.delete(txkey)
        return

    def get_transaction_iterator(self) -> Generator[Transaction, None, None]:
        """Get list of transactions."""
        for raw_data in self.db.iterator(prefix=b'trans_', include_key=False):
            tx = Transaction.deserialise(raw_data)
            yield tx
        return

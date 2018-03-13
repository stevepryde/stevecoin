"""Class for performing queries on the blockchain."""

# pylint: disable=unused-import
from typing import List, Set, TYPE_CHECKING
# pylint: enable=unused-import

from .block import Block, MAX_TRANSACTIONS_PER_BLOCK
from .crypto import (CryptoAddress, ECDSAPublicKey,
                     Hash512, Hasher, KeyValidationError)
from .errors import (TransactionDuplicateInputError,
                     TransactionNotFoundError, TransactionValidationError)
from .transaction import Transaction


if TYPE_CHECKING:
    # pylint: disable=unused-import
    from .blockdb import BlockDB
    from .transdb import TransDB
    # pylint: enable=unused-import


class QueryLayer:
    """Query the blockchain."""

    def __init__(self, bdb: 'BlockDB', tdb: 'TransDB') -> None:
        """Create a new QueryLayer object."""
        self.blockdb = bdb
        self.transdb = tdb
        return

    def get_transaction_from_blockchain(self, txid: Hash512) -> Transaction:
        """Get a transaction from the blockchain."""
        return self.blockdb.get_transaction(txid)

    def get_transaction_from_pending(self, txid: Hash512) -> Transaction:
        """Get a transaction from the pending transactions pool."""
        return self.transdb.get_transaction(txid)

    def add_transaction_to_pending(self, tx: Transaction) -> None:
        """Add transaction to the pending transactions pool."""
        self.transdb.add_transaction(tx)
        return

    def get_utxo(self, txid: Hash512, address: CryptoAddress) -> int:
        """Get a UTXO from the blockchain."""
        amount = self.blockdb.get_utxo_amount(txid, address)

        # Also verify that this transaction is legit.
        if txid != Hasher(b"Genesis").get_hash():
            trans = self.get_transaction_from_blockchain(txid)
            found = False
            for txoutput in trans.outputs:
                if address == txoutput.address:
                    found = True
                    assert txoutput.amount == amount, "UTXO amount mismatch"

            if not found:
                raise TransactionNotFoundError("UTXO not found")
        return amount

    def get_block(self, block_index: int) -> Block:
        """Get the specified block from the blockchain."""
        return self.blockdb.get_block(block_index)

    def get_num_blocks(self) -> int:
        """Return the number of blocks in the blockchain."""
        return self.blockdb.num_blocks

    def get_txids_for_address(self, pubkey: ECDSAPublicKey,
                              sig: Hash512) -> List[Hash512]:
        """
        Get all (unspent) input TXIDs for the specified address.

        NOTE: This requires a sig that contains the address, signed by the
        private key. Only the owner of the address can perform this query.
        """
        try:
            address = pubkey.get_address()
            Hasher([address.serialise()]).verify_signature(sig, pubkey)
        except (AssertionError, KeyValidationError):
            raise PermissionError("Permission denied")

        return self.blockdb.get_txids_for_address(address)

    def get_utxo_private(self, pubkey: ECDSAPublicKey, txid: Hash512,
                         sig: Hash512) -> int:
        """
        Get UTXO for the specified address.

        NOTE: This requires a sig that contains the txid and address, signed
        by the private key. Only the owner of the address can perform this
        query.
        """
        try:
            address = pubkey.get_address()
            Hasher([txid, address.serialise()]).verify_signature(sig, pubkey)
        except (AssertionError, KeyValidationError):
            raise PermissionError("Permission denied")

        return self.get_utxo(txid, address)

    def get_pending_transactions(self) -> List[Transaction]:
        """Get pending transactions."""
        limit = MAX_TRANSACTIONS_PER_BLOCK

        known_inputs = set()  # type: Set[Hash512]
        txlist = []
        txdelete = []
        for tx in self.transdb.get_transaction_iterator():
            try:
                tx.validate(self)
                tx.check_duplicates(known_inputs)
                txlist.append(tx)
                if len(txlist) == int(limit):
                    break
            except TransactionDuplicateInputError:
                # Transaction contains an input already in the list.
                # Skip it - so that it will be included in the next block,
                # if it is valid.
                continue
            except TransactionValidationError:
                txdelete.append(tx)

        # Delete any invalid transactions.
        for tx in txdelete:
            self.transdb.delete_transaction(tx.txid)
        return txlist

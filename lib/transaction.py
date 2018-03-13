"""Transaction classes."""

import json
from typing import Any, Dict, List, Set, TYPE_CHECKING

import base58

from .crypto import (basic_hash_check, CryptoAddress, ECDSAPublicKey,
                     Hash512, Hasher, KeyValidationError)
from .errors import (TransactionDuplicateInputError,
                     TransactionNotFoundError, TransactionValidationError)

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from querylayer import QueryLayer
    # pylint: enable=unused-import


TRANSACTION_CURRENT_VERSION = 1


class TransactionInput:
    """Transaction input class."""

    def __init__(self, txid: Hash512, pubkey: Hash512, sig: Hash512) -> None:
        """Create a new TransactionInput."""
        self.txid = txid
        self.pubkey = pubkey
        self.sig = sig
        return

    @staticmethod
    def from_dict(data: Dict[str, str]) -> 'TransactionInput':
        """Deserialise from a dict."""
        try:
            return TransactionInput(
                txid=Hash512.deserialise(data['txid']),
                pubkey=Hash512.deserialise(data['pubkey']),
                sig=Hash512.deserialise(data['sig'])
            )
        except KeyError as exc:
            raise TransactionValidationError("Bad transaction input") from exc

    def to_dict(self) -> Dict[str, str]:
        """Serialise to a dict."""
        return {
            'txid': self.txid.serialise(),
            'pubkey': self.pubkey.serialise(),
            'sig': self.sig.serialise()
        }

    def get_hash(self) -> Hash512:
        """Get the hash of this input."""
        return Hasher([
            self.txid,
            self.pubkey,
            self.sig
        ]).get_hash()

    def consistency_check(self) -> None:
        """Perform basic consistency check."""
        try:
            basic_hash_check(self.txid)
            ECDSAPublicKey(self.pubkey)
            basic_hash_check(self.sig)
            return
        except AssertionError as exc:
            raise TransactionValidationError("Invalid input") from exc


class TransactionOutput:
    """Transaction output class."""

    def __init__(self, address: CryptoAddress, amount: int) -> None:
        """Create a new TransactionOutput."""
        self.address = address
        self.amount = amount
        return

    @staticmethod
    def from_dict(data: Dict[str, str]) -> 'TransactionOutput':
        """Deserialise from a dict."""
        try:
            return TransactionOutput(
                address=CryptoAddress.deserialise(data['address']),
                amount=int(data['amount'])
            )
        except KeyError as exc:
            raise TransactionValidationError("Bad transaction output") from exc

    def to_dict(self) -> Dict[str, str]:
        """Serialise to a dict."""
        return {
            'address': self.address.serialise(),
            'amount': str(int(self.amount))
        }

    def get_hash(self) -> Hash512:
        """Calculate and return the hash of this output."""
        return Hasher([
            self.address.to_string(),
            str(self.amount)
        ]).get_hash()

    def consistency_check(self) -> None:
        """Perform basic consistency check."""
        if not isinstance(self.amount, int) or self.amount <= 0:
            raise TransactionValidationError("Invalid output amount")

        try:
            base58.b58decode_check(self.address.to_string())
            return
        except ValueError as exc:
            raise TransactionValidationError(
                "Invalid output address") from exc


class Transaction:
    """Transaction class with unencrypted data."""

    def __init__(self, inputs: List[TransactionInput],
                 outputs: List[TransactionOutput]) -> None:
        """Create a new Transaction object."""
        self.txid = Hash512(b'')
        self.version = TRANSACTION_CURRENT_VERSION

        self.outputs = outputs
        self.output_hash = Hash512(b'')  # Hash of hashes of all outputs.
        self.inputs = inputs
        self.input_hash = Hash512(b'')  # Hash of hashes of all inputs.
        return

    @staticmethod
    def deserialise(data: str) -> 'Transaction':
        """Deserialise str into Transaction object."""
        d = json.loads(data)
        return Transaction.deserialise_dict(d)

    @staticmethod
    def deserialise_dict(d: Dict[str, Any]) -> 'Transaction':
        """Deserialise dict into Transaction object."""
        version = d.get('version', 0)
        if version == 1:
            inputs = [TransactionInput.from_dict(x) for x in
                      d['inputs']]
            outputs = [TransactionOutput.from_dict(x) for x in
                       d['outputs']]
            t = Transaction(inputs, outputs)
            t.txid = Hash512.deserialise(d['txid'])
            t.version = version
            t.output_hash = Hash512.deserialise(d['output_hash'])
            return t

        raise Exception("Unknown transaction version: {}".format(version))

    def serialise(self) -> str:
        """Serialise the transaction and return str."""
        if self.version == 1:
            return json.dumps({
                'txid': self.txid.serialise(),
                'version': self.version,
                'outputs': [x.to_dict() for x in self.outputs],
                'output_hash': self.output_hash.serialise(),
                'inputs': [x.to_dict() for x in self.inputs]
            })

        raise Exception("Unknown transaction version: {}".format(self.version))

    def calculate_output_hash(self) -> Hash512:
        """Hash all the outputs."""
        return Hasher([
            x.get_hash() for x in self.outputs
        ]).get_hash()

    def calculate_input_hash(self) -> Hash512:
        """Hash all the inputs."""
        return Hasher([
            x.get_hash() for x in self.inputs
        ]).get_hash()

    def calculate_txid(self) -> Hash512:
        """Calculate the transaction id, using hashes."""
        return Hasher([
            str(self.version),
            self.calculate_output_hash(),
            self.calculate_input_hash()
        ]).get_hash()

    def consistency_check(self) -> None:
        """Perform a basic internal consistency check."""
        known_inputs = set()  # type: Set[Hash512]

        if not self.inputs:
            raise TransactionValidationError("Invalid inputs")

        if not self.outputs:
            raise TransactionValidationError("Invalid outputs")

        try:
            self.check_duplicates(known_inputs)
        except TransactionDuplicateInputError as exc:
            # Raise a validation error - because a duplicate here means
            # duplicate within a single transaction.
            raise TransactionValidationError("Duplicate inputs") from exc

        known_outputs = set()  # type: Set[CryptoAddress]
        for txoutput in self.outputs:
            txoutput.consistency_check()

            if txoutput.address in known_outputs:
                raise TransactionValidationError(
                    "Duplicate transaction output found")
            known_outputs.add(txoutput.address)

        if self.calculate_output_hash() != self.output_hash:
            raise TransactionValidationError(
                "Transaction output hash mismatch")

        if self.calculate_txid() != self.txid:
            raise TransactionValidationError(
                "Transaction ID mismatch")

        for txinput in self.inputs:
            # Verify the signature.
            try:
                pk = ECDSAPublicKey(txinput.pubkey)
                Hasher([
                    txinput.txid,
                    self.output_hash
                ]).verify_signature(txinput.sig, pk)
            except KeyValidationError as exc:
                raise TransactionValidationError("Invalid signature") from exc
        return

    def validate(self, q: 'QueryLayer') -> None:
        """Do a full validation of this transaction against the blockchain."""
        self.consistency_check()

        # Get input amount.
        total_input = 0
        total_output = 0

        for txinput in self.inputs:
            txaddress = ECDSAPublicKey(txinput.pubkey).get_address()
            try:
                total_input += q.get_utxo(txinput.txid, txaddress)
            except TransactionNotFoundError as exc:
                raise TransactionValidationError("Invalid input") from exc

        # Get total output and verify that it is <= input.
        for txoutput in self.outputs:
            total_output += txoutput.amount

        if total_output > total_input:
            raise TransactionValidationError("Output exceeds input")
        return

    def check_duplicates(self, known_inputs: Set[Hash512]) -> None:
        """Check that this transaction does not contain any known sigs."""
        for txinput in self.inputs:
            txinput.consistency_check()

            h = Hasher([txinput.txid, txinput.pubkey]).get_hash()

            if h in known_inputs:
                raise TransactionDuplicateInputError(
                    "Duplicate transaction input found")
            known_inputs.add(h)
        return

"""The main blockchain server."""

import getpass
import os
import sys

sys.path.append('.')  # noqa

# pylint: disable=C0413,C0411,W0611
from bottle import abort, error, get, post, request, response, route, run
from lib.blockchain import BlockChain
from lib.block import Block
from lib.crypto import ECDSAPublicKey, Hash512, BadSignatureError
from lib.errors import (BlockChainError, BlockNotFoundError,
                        BlockValidationError, TransactionNotFoundError,
                        TransactionValidationError)
from lib.transaction import Transaction

CHAIN = None


@get('/ping')
def ping():
    """Do basic test function."""
    return"pong"


@get('/miner')
def mine_it():
    """Get info for mining a block."""
    try:
        txlist = CHAIN.q.get_pending_transactions()
        num_blocks = CHAIN.q.get_num_blocks()
        last_block = CHAIN.q.get_block(num_blocks - 1)

        return{
            'txlist': [x.serialise() for x in txlist],
            'num_blocks': num_blocks,
            'prev_hash': last_block.hash.serialise(),
            'pow': CHAIN.blockdb.pow_difficulty
        }
    except BlockChainError:
        abort(400, "Blockchain error")


@get('/block/<index>')
def get_block(index):
    """Get block at the specified index."""
    try:
        block = CHAIN.q.get_block(index)
        response.content_type = "application/json"
        return block.serialise()
    except BlockNotFoundError:
        abort(404, "Block not found")
    except BlockChainError:
        abort(500, "Blockchain error")


@get('/txid/<txid>')
def get_transaction(txid):
    """Get transaction by txid."""
    try:
        tx = CHAIN.q.get_transaction_from_blockchain(txid)
        response.content_type = "application/json"
        return tx.serialise()
    except TransactionNotFoundError:
        abort(404, "Transaction not found")
    except BlockChainError:
        abort(500, "Blockchain error")


@post('/address/utx')
def txids_for_address():
    """Get all (unspent) txids for this address."""
    try:
        if not request.json:
            abort(400, "Invalid request")

        data = dict(request.json)
        pubkey_raw = data['pubkey']
        sig_raw = data['sig']

        assert pubkey_raw, "Invalid pubkey"
        assert sig_raw, "Invalid sig"

        pubkey = ECDSAPublicKey(Hash512.deserialise(pubkey_raw))
        sig = Hash512.deserialise(sig_raw)

        txids = CHAIN.q.get_txids_for_address(pubkey, sig)
        txids_str = [x.serialise() for x in txids]
        return {"data": txids_str}
    except (AssertionError, KeyError):
        abort(400, "Invalid request")
    except PermissionError:
        abort(403, "Permission denied")
    except BadSignatureError:
        abort(403, "Permission denied (Bad signature)")
    except BlockChainError:
        abort(500, "Blockchain error")


@post('/address/utxo')
def utxo_for_address_and_txid():
    """Get UTXO amount for the specified address and txid."""
    try:
        if not request.json:
            abort(400, "Invalid request")

        data = dict(request.json)
        pubkey_raw = data['pubkey']
        txid_raw = data['txid']
        sig_raw = data['sig']

        assert pubkey_raw, "Invalid pubkey"
        assert txid_raw, "Invalid txid"
        assert sig_raw, "Invalid sig"

        pubkey = ECDSAPublicKey(Hash512.deserialise(pubkey_raw))
        txid = Hash512.deserialise(txid_raw)
        sig = Hash512.deserialise(sig_raw)
        amount = CHAIN.q.get_utxo_private(pubkey, txid, sig)
        return {"data": amount}
    except (AssertionError, KeyError):
        abort(400, "Invalid request")
    except PermissionError:
        abort(403, "Permission denied")
    except BadSignatureError:
        abort(403, "Permission denied (Bad signature)")
    except BlockChainError:
        abort(500, "Blockchain error")


@post('/address/balance')
def utxo_for_address():
    """Get total UTXO amount for the specified address."""
    try:
        if not request.json:
            abort(400, "Invalid request")

        data = dict(request.json)
        pubkey_raw = data['pubkey']
        sig_raw = data['sig']

        assert pubkey_raw, "Invalid pubkey"
        assert sig_raw, "Invalid sig"

        pubkey = ECDSAPublicKey(Hash512.deserialise(pubkey_raw))
        sig = Hash512.deserialise(sig_raw)

        amount = 0
        txids = CHAIN.q.get_txids_for_address(pubkey, sig)
        address = pubkey.get_address()

        for txid in txids:
            amount += CHAIN.q.get_utxo(txid, address)

        return {"data": amount}
    except (AssertionError, KeyError) as exc:
        abort(400, "Invalid request: {}".format(exc))
    except PermissionError:
        abort(403, "Permission denied")
    except BadSignatureError:
        abort(403, "Permission denied (Bad signature)")
    except BlockChainError:
        abort(500, "Blockchain error")


@post('/tx/submit')
def transaction_submit():
    """Submit a new transaction to the pool."""
    try:
        if not request.json:
            abort(400, "Invalid transaction")

        tx = Transaction.deserialise_dict(request.json)
        tx.validate(CHAIN.q)
        CHAIN.q.add_transaction_to_pending(tx)
    except TransactionValidationError as exc:
        abort(400, "Invalid transaction: {}".format(exc))
    except BlockChainError:
        abort(500, "Blockchain error")


@post('/block/submit')
def block_submit():
    """Submit a new block to the blockchain."""
    try:
        if not request.json:
            abort(400, "Invalid block")

        block = Block.deserialise_dict(request.json)
        CHAIN.blockdb.write_new_block(block, CHAIN.q)
        # Delete transactions from pending.
        for tx in block.transactions:
            CHAIN.transdb.delete_transaction(tx.txid)
        return"SUCCESS"
    except BlockValidationError as exc:
        abort(400, "Invalid block: {}".format(exc))
    except BlockChainError:
        abort(500, "Blockchain error")


@error(500)
def handle_500(details):
    """Error handler for HTTP 500."""
    return {'error': 'Unknown error: {}'.format(details)}


if __name__ == '__main__':
    cur_dir = os.path.realpath(os.path.dirname(__file__))
    base_dir = os.path.join(cur_dir, 'blockdata')
    create_flag = False
    password = ''
    if not os.path.exists(base_dir):
        # Blockchain not found. Create a new one.
        print("Blockchain not found. A new blockchain will be created.")

        try:
            while True:
                print("\nNOTE: Password will not be displayed while typing.")
                password = getpass.getpass(
                    prompt="Please enter a password for the private key: ")
                try:
                    assert len(password) >= 8, \
                        "Password must be at least 8 characters long"

                    password_repeat = getpass.getpass(
                        prompt="Please re-enter the password again: ")
                    if password_repeat == password:
                        break

                    print("Passwords do not match. Please try again.")
                except AssertionError as exc:
                    print("Invalid password: {}".format(exc))
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(1)

        os.makedirs(base_dir)
        create_flag = True

    CHAIN = BlockChain(base_dir=base_dir)
    if create_flag and password and CHAIN.q.get_num_blocks() == 0:
        CHAIN.create(passphrase=password)
        print("Blockchain created successfully.")
    elif CHAIN.q.get_num_blocks() < 1:
        print("Blockchain is empty. Please delete the '{}' directory to "
              "create a new one.".format(CHAIN.base_dir))
        print("WARNING: Deleting an existing blockchain directory will "
              "destroy the blockchain and any outstanding transactions!")
        sys.exit(1)

    try:
        port = int(os.environ.get('BLOCKCHAIN_PORT')) or 5000
    except (TypeError, ValueError):
        port = 5000

    print("Starting server on port {} ...\n".format(port))
    run(host='localhost', port=port, debug=True)

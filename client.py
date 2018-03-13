"""Command-line client for the blockchain."""

import argparse
import getpass
import json
import os
import sys
from typing import Any, Dict, Optional

import requests

from lib.crypto import (CryptHelper, ECDSAPrivateKey,
                        EncryptedData, Hasher, Hash512)

CONFIG_FILENAME = "config.sc"
MASTER_PASSWORD = None
GLOBAL_CONFIG = None

DEBUG_MODE = True

if DEBUG_MODE:
    MASTER_PASSWORD = os.environ.get('BLOCKCHAIN_DEBUG_PASSWORD')


def exit_with_error(message: str, code: int = 1) -> None:
    """Exit with the specified error message."""
    print(message)
    sys.exit(code)


def get_master_password(first: bool = False) -> str:
    """Get the master password from cache, or prompt for it."""
    global MASTER_PASSWORD
    if MASTER_PASSWORD:
        return MASTER_PASSWORD

    if first:
        try:
            while True:
                password = getpass.getpass(
                    prompt="Please specify a master password for encrypting "
                    "the configuration: ")
                try:
                    assert len(password) >= 8, \
                        "Password must be at least 8 characters long"

                    password_repeat = getpass.getpass(
                        prompt="Please re-enter the same password again: ")
                    if password_repeat == password:
                        break

                    print("Passwords do not match. Please try again.")
                except AssertionError as exc:
                    print("Invalid password: {}".format(exc))
        except KeyboardInterrupt:
            exit_with_error("\nCancelled.", 2)

        MASTER_PASSWORD = password
        return MASTER_PASSWORD

    try:
        while True:
            password = getpass.getpass(
                prompt="Please enter your master password: ")
            try:
                assert len(password) >= 8, \
                    "Password must be at least 8 characters long"
                break
            except AssertionError as exc:
                print("Invalid password: {}".format(exc))
    except KeyboardInterrupt:
        exit_with_error("\nCancelled.", 2)

    MASTER_PASSWORD = password
    return MASTER_PASSWORD


def save_config(config: Dict[str, Any]) -> None:
    """Save the current config to file."""
    global MASTER_PASSWORD
    assert MASTER_PASSWORD, "Error: Master password not set!"

    cur_dir = os.path.realpath(os.path.dirname(__file__))
    config_path = os.path.join(cur_dir, CONFIG_FILENAME)

    config_data = json.dumps(config).encode('utf-8')
    encrypted = CryptHelper.encrypt_with_passphrase(config_data,
                                                    MASTER_PASSWORD)
    encrypted.write_to_file(config_path, overwrite_if_exists=True)

    global GLOBAL_CONFIG
    GLOBAL_CONFIG = config
    return


def get_config() -> Dict[str, Any]:
    """Get the config from file."""
    global GLOBAL_CONFIG
    if GLOBAL_CONFIG:
        return GLOBAL_CONFIG

    cur_dir = os.path.realpath(os.path.dirname(__file__))
    config_path = os.path.join(cur_dir, CONFIG_FILENAME)

    if not os.path.exists(config_path):
        print("Config file not found. It will be created...")
        # Create configuration.
        config = {
            'server': 'http://localhost:5000',
            'pks': []
        }

        get_master_password(first=True)
        save_config(config)
        print("Server: {}".format(config['server']))
        return config

    password = get_master_password()
    try:
        encrypted = EncryptedData.read_from_file(config_path)
    except IOError as exc:
        print("Error reading config from file '{}': {}".
              format(config_path, exc))

    try:
        config_raw = encrypted.decrypt_with_passphrase(password)
        config = json.loads(config_raw)
    except Exception as exc:  # pylint: disable=W0703
        exit_with_error("Error decrypting config: {}".format(exc))

    print("Server: {}".format(config['server']))
    GLOBAL_CONFIG = config
    return config


def server_get(url: str, params: Optional[Dict[str, str]] = None) \
        -> requests.Response:
    """Process the HTTP GET request to the server."""
    config = get_config()
    if not config['server']:
        exit_with_error("No server URL set. Please use --server to set one.")
    return requests.get(config['server'] + url, params=params)


def server_post(url: str, data: Optional[Dict[str, Any]] = None) \
        -> requests.Response:
    """Process the HTTP POST request to the server."""
    config = get_config()
    if not config['server']:
        exit_with_error("No server URL set. Please use --server to set one.")
    return requests.post(config['server'] + url, json=data)


# pylint: disable=R0914
def submit_transaction(src: str, dest: str, amount: Optional[int] = None,
                       transfer_all: bool = False) -> None:
    """Process the specified transfer."""
    config = get_config()
    config.setdefault('pks', [])

    if not config['pks']:
        exit_with_error("No src addresses found. Please create an address "
                        "and transfer funds before trying again.")

    # Find the appropriate src pk.
    pk = None
    for pk_raw in config['pks']:
        pk_temp = ECDSAPrivateKey.from_string(pk_raw)
        if pk_temp.publickey.get_address().to_string() == src:
            pk = pk_temp
            break

    if not pk:
        exit_with_error("Unknown src address. Please add the private key for "
                        "this address and try again.")

    pubkey = pk.publickey
    sig = Hasher([src]).sign(pk)

    r = server_post('/address/balance', data={
        'pubkey': pubkey.as_hash().serialise(),
        'sig': sig.serialise()
    })

    if r.status_code != 200:
        exit_with_error(
            "Error getting balance for address: {}".format(src))

    total_input = r.json().get('data')

    if transfer_all:
        amount = total_input
    elif total_input < amount:
        exit_with_error("Insufficient funds in src address: {}".format(src))

    # Get src txids for address.
    r = server_post('/address/utx', data={
        'pubkey': pubkey.as_hash().serialise(),
        'sig': sig.serialise()
    })

    if r.status_code != 200:
        exit_with_error("Error getting transactions for src address.")

    txids = r.json().get('data')

    # The input sigs must be signed using the output hash.
    output_list = [{
        'address': dest,
        'amount': str(int(amount))
    }]

    # Remainder needs to go to a new address.
    remainder_address = None
    remainder = 0
    if total_input > amount:
        remainder = total_input - amount
        remainder_address = get_new_address()
        assert remainder_address, \
            "Unknown remainder address. Transaction cancelled."
        output_list.append({
            'address': remainder_address,
            'amount': str(int(remainder))
        })

    output_hasher = Hasher()
    for output in output_list:
        h = Hasher([output.get('address'), output.get('amount')])
        output_hasher.update(h.get_hash())

    output_hash = output_hasher.get_hash()

    input_list = []
    input_hasher = Hasher()
    for txid_str in txids:
        # Create the transaction input.
        txid = Hash512.deserialise(txid_str)
        sig = Hasher([txid, output_hash]).sign(pk)
        input_list.append({
            'txid': txid_str,
            'pubkey': pubkey.as_hash().serialise(),
            'sig': sig.serialise()
        })

        h = Hasher([
            txid,
            pubkey.as_hash(),
            sig
        ])
        input_hasher.update(h.get_hash())

    input_hash = input_hasher.get_hash()

    txid_hasher = Hasher([
        str(1),  # version
        output_hash,
        input_hash
    ])

    trans = {
        'version': 1,
        'txid': txid_hasher.get_hash().serialise(),
        'inputs': input_list,
        'outputs': output_list,
        'output_hash': output_hash.serialise()
    }

    r = server_post('/tx/submit', data=trans)

    if r.status_code != 200:
        exit_with_error("Error submitting transaction: {}".format(r.text))

    # Display info about the transaction.
    print("Transaction submitted successfully:")
    print("Input address: {}".format(src))
    print("Transferred {} to address: {}".format(amount, dest))

    if remainder:
        assert remainder_address, "Unknown remainder address!"
        print("Transferred remainder of {} to newly created address: {}".
              format(remainder, remainder_address))
    return


def set_server_address(url: str) -> None:
    """Set the specified server address."""
    config = get_config()
    config['server'] = url
    save_config(config)
    print("Server is now set to: {}".format(url))
    return


def add_private_key(filename: str) -> None:
    """Add the specified private key from file."""
    password = getpass.getpass(
        "Please enter the password for '{}': ".format(filename))
    config = get_config()
    config.setdefault('pks', [])
    pks = config['pks']
    try:
        pk = ECDSAPrivateKey.from_file(filename, password)
    except ValueError:
        exit_with_error("Error loading private key (invalid password?)")

    pk_str = pk.to_string()
    if pk_str in pks:
        exit_with_error("Address already exists in wallet", 0)

    pks.append(pk_str)
    save_config(config)
    print("Added address: {}".format(
        pk.publickey.get_address().to_string()))
    return


def get_new_address() -> str:
    """Get a new address and return it as string."""
    config = get_config()
    config.setdefault('pks', [])
    pks = config['pks']
    pk = ECDSAPrivateKey.generate()

    pk_str = pk.to_string()
    if pk_str in pks:
        exit_with_error("Address already exists in wallet?!", 0)

    pks.append(pk_str)
    save_config(config)
    return pk.publickey.get_address().to_string()


def create_address() -> None:
    """Create a new private key and display the address."""
    address = get_new_address()
    print("Added new address: {}".format(address))
    return


def delete_address(address: str) -> None:
    """Delete the specified address (including all keys)."""
    config = get_config()
    config.setdefault('pks', [])

    if not config['pks']:
        exit_with_error("No private keys found.")

    # Find the appropriate src pk.
    pk = None
    for pk_raw in config['pks']:
        pk_temp = ECDSAPrivateKey.from_string(pk_raw)
        if pk_temp.publickey.get_address().to_string() == address:
            pk = pk_temp
            break

    if not pk:
        exit_with_error("No private key found for this address.")

    pubkey = pk.publickey
    sig = Hasher([address]).sign(pk)

    r = server_post('/address/balance', data={
        'pubkey': pubkey.as_hash().serialise(),
        'sig': sig.serialise()
    })

    if r.status_code != 200:
        exit_with_error(
            "Error getting balance for address: {}".format(address))

    balance = r.json().get('data')
    if balance != 0:
        exit_with_error("Cannot delete address '{}' due to non-zero "
                        "balance: {}".format(address, balance))

    config['pks'].remove(pk.to_string())
    save_config(config)
    print("Address '{}' removed.".format(address))
    return


def list_addresses() -> None:
    """List all current addresses and their balances."""
    config = get_config()
    config.setdefault('pks', [])
    if not config['pks']:
        print("No addresses currently exist in wallet")
        return

    rows = [
        ["Address", "Amount"],
        ["-------", "------"]
    ]

    for pk_raw in config['pks']:
        pk = ECDSAPrivateKey.from_string(pk_raw)
        pubkey = pk.publickey
        address = pubkey.get_address().to_string()

        sig = Hasher([address]).sign(pk)
        r = server_post('/address/balance', data={
            'pubkey': pubkey.as_hash().serialise(),
            'sig': sig.serialise()
        })

        if r.status_code != 200:
            exit_with_error(
                "Error getting balance for address: {}".format(address))

        amount = r.json().get('data')

        rows.append([address, str(amount)])

    col_width = max(len(word) for row in rows for word in row) + 2  # padding
    for row in rows:
        print("".join(word.ljust(col_width) for word in row))
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Stevecoin CLI Client")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--server', action='store', metavar='URL', type=str,
                       help="Specify the blockchain server to send requests "
                       "to")
    group.add_argument('--add-private-key', action='store', metavar="FILE",
                       type=str, help="Add the specified private key from an "
                       "encrypted PEM file.")
    group.add_argument('--create', action='store_true',
                       help="Create new address")
    group.add_argument('--delete', action='store', metavar='ADDRESS', type=str,
                       help="Delete address (balance must be 0)")
    group.add_argument('--list', action='store_true', help="List all "
                       "addresses and their current balance")
    group.add_argument('--transfer', action='store_true',
                       help="Transfer --amount coins from --src to --dest")

    tgroup = parser.add_argument_group('Options required for --transfer')
    tgroup.add_argument('--src', action='store', metavar="ADDRESS", type=str,
                        help="Specify the source address to transfer coins "
                        "from")
    tgroup.add_argument('--dest', action='store', metavar="ADDRESS", type=str,
                        help="Specify the destination address to transfer "
                        "coins to")
    tgroup.add_argument('--amount', action='store', metavar="AMOUNT", type=int,
                        help="Specify the number of coins to transfer "
                        "(To transfer all coins from src address, use --all "
                        "option instead)")
    tgroup.add_argument('--all', action='store_true', default=False,
                        help="If specified, all coins will be transferred "
                        "from src to dest")

    args = parser.parse_args()

    if args.transfer:
        if not args.src:
            parser.error("--transfer requires --src <address>")

        if not args.dest:
            parser.error("--transfer requires --dest <address>")

        if not args.amount and not args.all:
            parser.error("--transfer requires either --amount <amount> or "
                         "--all")

        submit_transaction(src=args.src, dest=args.dest, amount=args.amount,
                           transfer_all=args.all)
        sys.exit(0)

    if args.src or args.dest or args.amount or args.all:
        parser.error("Invalid options specified without --transfer")

    if args.server:
        set_server_address(args.server)
    elif args.add_private_key:
        add_private_key(args.add_private_key)
    elif args.create:
        create_address()
    elif args.delete:
        delete_address(args.delete)
    elif args.list:
        list_addresses()
    else:
        parser.error("Unknown command")
    sys.exit(0)

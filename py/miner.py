"""Simple block miner."""

import argparse
import sys
import time

import requests


from lib.block import Block
from lib.crypto import Hash512
from lib.transaction import Transaction


def exit_with_error(message: str, code: int = 1) -> None:
    """Exit with the specified error message."""
    print(message)
    sys.exit(code)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Stevecoin Miner")
    parser.add_argument('--server', action='store', metavar='URL', type=str,
                        required=True,
                        help="Specify the blockchain server to send requests "
                        "to")

    args = parser.parse_args()

    try:
        server_url = args.server
        print("Server: {}".format(server_url))

        print("Waiting for new transactions to mine ...")
        while True:
            # Get transactions from server.
            r = requests.get(server_url + "/miner")
            if r.status_code != 200:
                exit_with_error("Error getting pending transactions")

            data = r.json()
            txlist = data.get('txlist')
            if not txlist:
                time.sleep(60)
                continue

            next_index = data.get('num_blocks')
            prev_hash_raw = data.get('prev_hash')
            pow_difficulty = data.get('pow')

            if not next_index or not prev_hash_raw or not pow_difficulty:
                exit_with_error("Server returned invalid info")

            prev_hash = Hash512.deserialise(prev_hash_raw)

            print("Mining block {} ...".format(next_index))
            block = Block(index=next_index, prev_hash=prev_hash)
            block.transactions = [Transaction.deserialise(x) for x in txlist]
            block.merkle_root = block.calculate_merkle_root()
            block.hash = block.calculate_hash()
            block.ensure_difficulty(pow_difficulty)

            r = requests.post(server_url + "/block/submit",
                              json=block.serialise_dict())
            if r.status_code != 200:
                exit_with_error("Error submitting block")

            print("Successfully mined block {}".format(block.index))
            print("Waiting for new transactions to mine ...")
    except KeyboardInterrupt:
        print("Exiting.")

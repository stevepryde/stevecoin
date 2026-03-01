# SteveCoin

A personal project to create my own fully functioning cryptocurrency,
in order to better understand the technologies involved.

## Usage

### Server

To run the server:

    $ python index.py

The first time you run it, you will be prompted to enter a password.
This is the password used to encrypt the private key for the genesis
transaction.

On all subsequent runs, the server will load the existing blockchain,
and will perform a full consistency check on startup.

All data will be stored in the blockdata/ directory, including the
keys for the genesis transaction.

### Client

To run the client:

    $ python client.py --help

The first time you run it, you will be prompted to enter a master password.
This password will be used to encrypt the configuration file, because this
file will contain all private keys associated with this client.

Create as many addresses as you want using the --create option.

Note that these address will not work with any other cryptocurrency!

### Miner

To run the miner on your local server:

    $ python miner.py --server http://localhost:5000

The miner will query the server for any pending transactions, and if any
exist, it will mine them into a block and submit that new block to the
server. The server will then validate the block and if successful, will
write it to the blockchain.

The miner will run indefinitely, polling for new transactions every 60 seconds.

## Example

Start the server:

    $ python index.py

Enter the master password if this is the first run.

You should see something like this:

    $ python index.py
    Blockchain not found. A new blockchain will be created.

    NOTE: Password will not be displayed while typing.
    Please enter a password for the private key:
    Please re-enter the password again:
    Creating new blockchain...
    Mining Genesis Block...
    Writing Genesis Block...
    Consistency check passed...
    Blockchain created successfully.
    Starting server on port 5000 ...

    Bottle v0.12.13 server starting up (using WSGIRefServer())...
    Listening on http://localhost:5000/
    Hit Ctrl-C to quit.


In a second terminal session, run the miner:

    $ python miner.py --server http://localhost:5000
    Server: http://localhost:5000
    Waiting for new transactions to mine ...


In a third terminal session, list all client addresses:

    $ python client.py --list
    Config file not found. It will be created...
    Please specify a master password for encrypting the configuration:
    Please re-enter the same password again:
    Server: http://localhost:5000
    No addresses currently exist in wallet

Enter a master password if this is the first run of the client.

Add the genesis private key to the client:

    $ python client.py --add-private-key blockdata/genesis_key_private.pem
    Please enter the password for 'blockdata/genesis_key_private.pem':
    Please enter your master password:
    Server: http://localhost:5000
    Added address: 1NZ4xx9bgTCzdjXzDA2bEGfr2opCkJh6UX

You will be prompted for both the password for the genesis key (the first
one you entered in this example) and the master client password.

The address you see will be different than the example above.

Create a new (empty) address:

    $ python client.py --create
    Please enter your master password:
    Server: http://localhost:5000
    Added new address: 14emQmpLXA1KbT2BT6Yt87MAgGcdJaYkZH

Once again your address will be different than the example given.

List all balances (the genesis balance should now show up):

    $ python client.py --list
    Please enter your master password:
    Server: http://localhost:5000
    Address                             Amount
    -------                             ------
    1NZ4xx9bgTCzdjXzDA2bEGfr2opCkJh6UX  987654321000
    14emQmpLXA1KbT2BT6Yt87MAgGcdJaYkZH  0

Transfer some coin from the genesis address to the new address:

    $ python client.py --transfer --src 1NZ4xx9bgTCzdjXzDA2bEGfr2opCkJh6UX --dest 14emQmpLXA1KbT2BT6Yt87MAgGcdJaYkZH --amount 100
    Please enter your master password:
    Server: http://localhost:5000
    Transaction submitted successfully:
    Input address: 1NZ4xx9bgTCzdjXzDA2bEGfr2opCkJh6UX
    Transferred 100 to address: 14emQmpLXA1KbT2BT6Yt87MAgGcdJaYkZH
    Transferred remainder of 987654320900 to newly created address: 17oRYq8iC7M78K8p86PgtEmTuZLqe5JyEZ

Wait for the miner to mine the block. You will see something like the following output from the miner:

    Mining block 1 ...
    Successfully mined block 1
    Waiting for new transactions to mine ...

Then check the balances:

    $ python client.py --list
    Please enter your master password:
    Server: http://localhost:5000
    Address                             Amount
    -------                             ------
    1NZ4xx9bgTCzdjXzDA2bEGfr2opCkJh6UX  0
    14emQmpLXA1KbT2BT6Yt87MAgGcdJaYkZH  100
    17oRYq8iC7M78K8p86PgtEmTuZLqe5JyEZ  987654320900

As you can see - we successfully transferred 100 coins from the genesis
address to the new address. Each transaction also automatically deposits
any remaining coins into a newly created address, rather than transferring
them back to the original address. This leaves the original address with 0
coins. You can delete the original address using the --delete option if you
wish.

Feel free to play around with it some more.

Enjoy!

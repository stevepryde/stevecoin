# Bugs found in the Python implementation

Discovered during the Rust port. All fixed in both Python and Rust.

## 1. Genesis block hash validation is wrong (block.py:200) — FIXED

In `Block.validate()`, when verifying a genesis block on a brand-new blockchain
(no blocks yet), the code checked:

```python
assert self.hash == Hasher(GENESIS_HASH).get_hash(), "Block hash mismatch"
```

But the genesis block's hash is computed via `calculate_hash()` which includes
the version, index, timestamp, merkle root, salt, and nonce — not just the
GENESIS_HASH bytes. So this check would always fail.

**Fix:** Removed the incorrect hash comparison. The `num_blocks == 0` check is
sufficient for validating a genesis block on a brand-new blockchain. Rust
version was already correct.

## 2. Proof-of-work difficulty is never persisted (blockdb.py) — FIXED

`pow_difficulty` is read from LevelDB key `sc_pow`, but this key was never
written anywhere in the codebase. Additionally, `num_blocks` was not being
decoded from its packed integer format.

**Fix:** Added `sc_pow` persistence on first initialization (both Python and
Rust). Fixed `num_blocks` decoding to use `unpackint()` in Python.

## 3. DEBUG_MODE hardcoded to True (client.py:19) — FIXED

```python
DEBUG_MODE = True
```

This meant the client would always check the `BLOCKCHAIN_DEBUG_PASSWORD`
environment variable and use it if set, bypassing interactive password prompts.

**Fix:** Set `DEBUG_MODE = False` in Python. In Rust, gated the env var check
behind `#[cfg(debug_assertions)]` so it only works in debug builds.

## 4. Missing spaces before return values (index.py) — FIXED

Several handlers had missing spaces between `return` and the value:

- `return"pong"` → `return "pong"`
- `return{` → `return {`
- `return"SUCCESS"` → `return "SUCCESS"`

**Fix:** Added spaces. Rust version was already correct.

## 5. Naive vs UTC timestamp comparison (block.py:182-185) — FIXED

Block timestamps are created with UTC (`datetime.timezone.utc`), but validation
used `datetime.datetime.fromtimestamp()` (local time) and compared against
`datetime.datetime.now()` (also local time, but naive).

**Fix:** Changed to `datetime.fromtimestamp(ts, tz=timezone.utc)` and
`datetime.now(timezone.utc)`. Rust version was already correct (uses
`SystemTime`/`UNIX_EPOCH`).

## 6. Port 0 silently ignored (index.py:254) — FIXED

```python
port = int(os.environ.get('BLOCKCHAIN_PORT')) or 5000
```

If `BLOCKCHAIN_PORT` is set to `"0"`, then `int("0") = 0`, and `0 or 5000`
evaluates to `5000`, silently ignoring the explicitly-set port.

**Fix:** Changed to check `is not None` instead of using `or`. Rust version
was already correct (uses `.unwrap_or(5000)`).

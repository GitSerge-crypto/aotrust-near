# `merkle-anchor` — NEAR anchor contract

One purpose: store a Merkle root per sequence number, permanently, on chain. It does no hashing,
no validation and no access control beyond "the contract account may append". That is deliberate —
the contract is small enough to read in one screen (`src/lib.rs`, 44 lines) and to audit.

Deployed as **`notary-node.near`** on NEAR mainnet.

## State

```rust
pub struct MerkleAnchor {
    roots: LookupMap<u64, String>,  // anchor_seq -> root, 64 lowercase hex chars
    sequence: u64,                  // number of roots stored, i.e. next anchor_seq
}
```

## Methods

| method | kind | arguments | returns |
|---|---|---|---|
| `new()` | `#[init]` | — | initialises empty state |
| `anchor(root: String)` | call (writes) | `{"root": "<64 hex chars>"}` | `u64` — the sequence number assigned to this root |
| `get_root(seq: u64)` | view (free) | `{"seq": <u64>}` | the root for that sequence: the 32-byte Merkle root as a 64-character hex string, JSON-serialised; `null` if the sequence was never assigned |
| `sequence()` | view (free) | — | `u64` — how many roots are stored; also the next `anchor_seq` |

`anchor()` writes `roots[sequence] = root`, increments `sequence`, and returns the sequence it used.
Sequence numbers are dense and start at `0`.

`get_root()` returns an `Option<String>`, so a JSON-RPC `result` field decodes to either
`"<64 hex>"` or `null`. It is a string, not a byte array: parsers must not expect 32 raw bytes.

## Who can write

Only the contract account itself:

```rust
assert_eq!(
    near_sdk::env::predecessor_account_id(),
    near_sdk::env::current_account_id(),
    "Only contract account may anchor roots"
);
```

Consequences, stated plainly:

- Writing requires a transaction signed with a key on `notary-node.near`. There is no owner field,
  no admin list, no writer allowlist, and no separate role for the notary operator — the operator
  holds a function-call key on the contract account.
- Reading requires nothing. `get_root` and `sequence` are view methods: any RPC, any client, no key,
  no permission, no gas.
- No method updates or deletes a stored root. The only mutation is appending at `sequence`.
- Upgrading the contract's code is controlled by the account's full-access key, as on any NEAR
  account. This is the one piece of trust that is not in the contract's own code, and it is why the
  exit kit exists: an operator who rewrites the contract cannot rewrite the exported receipts.

## What the contract does not check

`anchor()` accepts any `String`. It does not enforce a length, hex encoding, or freshness:

- a malformed root is stored as given (the client is responsible for sending 64 lowercase hex chars);
- a repeated root is accepted and stored under a new sequence number (anchoring the same log twice
  is legal, and `scripts/anchor.py` avoids it by comparing with the last recorded anchor);
- the contract does not prove the leaf set is complete — that check lives in
  `tools/aotrust_export.py roots`, which recomputes the root from `leaves.jsonl`.

## Storage and cost

`LookupMap` stores one entry per anchor, key `u64`, value a 64-character string — roughly 80–100
bytes of contract storage per anchor including NEAR's overhead. Storage grows linearly and forever,
so the account balance must cover it; there is no pruning by design, since deleting history would
defeat the purpose. `anchor()` itself is a few Wasm instructions; the client sends 30 Tgas, which is
far more than the call needs.

## Build

```bash
cd contract
cargo build --target wasm32-unknown-unknown --release
# or, with cargo-near installed:
cargo near build
```

Release profile: `opt-level="z"`, `overflow-checks=true`, `lto=true`, `strip=true`, `panic="abort"`,
`codegen-units=1`. Expected artefact size ≈ 62 KB.

`Cargo.toml` pins `near-sdk 5.6.0` with the `legacy` feature (the `LookupMap` API used here).
`Cargo.minimal.toml` is an older variant pinned to `near-sdk 4.1.1` and `src/lib_minimal.rs`; keep it
out of a normal build.

`build/merkle_anchor.wasm` is a prebuilt artefact of `src/lib.rs`, committed so reviewers can deploy
without a Rust toolchain.

## Deploy

```bash
near deploy notary-node.near \
  target/wasm32-unknown-unknown/release/merkle_anchor.wasm \
  --initFunction new --initArgs '{}'
```

## Read it without any of our code

```bash
python3 - <<'PY'
import json, base64, urllib.request
body = json.dumps({"jsonrpc":"2.0","id":1,"method":"query","params":{
    "request_type":"call_function","finality":"final","account_id":"notary-node.near",
    "method_name":"get_root","args_base64":base64.b64encode(b'{"seq":0}').decode()}}).encode()
r = json.load(urllib.request.urlopen(urllib.request.Request(
    "https://rpc.mainnet.near.org", data=body,
    headers={"Content-Type":"application/json"})))
print(bytes(r["result"]["result"]).decode())   # "63a62462…0d58"
PY
```

## Tests

There are no unit tests in this crate. It is an append-and-read map with one assertion; its
behaviour is exercised by the live anchors, and the exit kit checks the stored roots against roots
recomputed from the leaves. Tests are welcome — none are claimed here that do not exist.

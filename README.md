# AOTrust — NEAR Merkle anchor

Open core of AOTrust: a notary service that issues a fixed-size cryptographic receipt for a
file or an agent output, and publishes a Merkle root of its append-only log to a NEAR contract
once an hour. Nothing in this repository needs an AOTrust account, a key, or an AOTrust server
to be verified.

The claim this repository makes is narrow and testable: **a hash existed at a time, and you can
check that against NEAR without asking us.**

```yaml
# At a glance (machine-readable)
project: AOTrust
chain: NEAR mainnet
contract: notary-node.near
contract_source: contract/src/lib.rs
methods: [new, anchor, get_root, sequence]
log: append-only Merkle log, RFC 9162 (Certificate Transparency hashing)
anchor: one transaction per hour when new leaves exist; root stored as hex string by seq
receipt: 239 bytes = 175-byte payload + 64-byte Ed25519 signature
receipt_versions: [0x03, 0x04]
notary_pubkey: 490f51f23b993eacaff54fc977d9a7689ab7d4ae91504dc6cbdeadb2dbf1f462
exit_kit: tools/aotrust_export.py
inclusion_verifier: tools/verify_inclusion.py
browser_verifier: verify/index.html
anchor_script: scripts/anchor.py
license: MIT
```

## The problem

An agent hands over a deliverable. A week later the client says it was edited after delivery, or
the vendor says the record never existed. The file is the same; the argument is about **time and
existence**, and normally the party that owns the database wins it, because everyone else has to
take that database on faith.

Three properties remove that faith requirement:

1. **A receipt you can check offline** — the hash, the time, a signature, a Merkle root.
2. **A root published somewhere the vendor does not control** — here, a NEAR contract readable by
   anyone through any public RPC.
3. **An exit path** — if the vendor disappears, the receipts and the log must stay verifiable, and
   someone else must be able to continue the log.

This repository is the code for (2) and (3), plus the verifiers that make (1) checkable.

## Repository layout

| path | what it is |
|---|---|
| `contract/` | NEAR contract (`merkle-anchor`): stores one Merkle root per sequence number |
| `contract/README.md` | contract API, access control, build and deploy |
| `scripts/anchor.py` | standalone anchor job: `leaves.jsonl` → Merkle root → NEAR; dry run by default |
| `tools/aotrust_export.py` | exit kit: `export` / `verify` / `roots`, works on an exported directory |
| `tools/verify_inclusion.py` | offline Merkle inclusion-proof check (stdlib only, RFC 9162) |
| `verify/` | static browser page: recompute a hash, fold the proof, read `get_root` from a public RPC |
| `examples/leaves.jsonl` | 3 synthetic leaves showing the leaf file format (no client data) |
| `SECURITY.md` | how to report a vulnerability, scope, key policy |
| `DEMO_SCRIPT.md` | shot list for the 90-second demo recording |

## Try it

Everything below runs from a clone. No account, no key, no AOTrust server, no database. Steps 1–3
need nothing but Python 3.9+; step 4 needs `pynacl`; step 6 needs nothing but a browser.

### 1. Build a Merkle root and see exactly what would be sent to NEAR

```bash
python3 scripts/anchor.py --leaves examples/leaves.jsonl
```

→ the script sorts the leaves, builds the RFC 9162 tree, reads `sequence()` from the live contract,
and prints the transaction it *would* send. It sends nothing:

```
leaves: 3 (sorted by log_index, RFC 9162)
merkle root: 84cbdbc2c7b0cb0c1198c4f10a4cfef5a4456794e18a9b0ffc16f99ad1637f6a
tree size: 3
contract: notary-node.near @ https://rpc.mainnet.near.org
chain sequence: 97 -> anchor_seq 97          # 97 is whatever the contract reports right now
DRY RUN: would call anchor("84cbdbc2…37f6a") on notary-node.near (gas 30 Tgas)
DRY RUN: anchor_seq would be 97 (assigned by the contract, not by this script)
DRY RUN: no transaction sent, anchors.jsonl untouched
to send for real: export NEAR_ACCOUNT_KEY=... then add --send
```

No network at all? Add `--offline`, and the sequence line reports `skipped`. Machine-readable
output for CI: `--json` prints one JSON object instead of the block above.

Sending is opt-in and needs a key in the environment only:

```bash
export NEAR_ACCOUNT_KEY='{"account_id":"notary-node.near","secret_key":"ed25519:…"}'
python3 scripts/anchor.py --leaves leaves.jsonl --send
```

### 2. Check a Merkle inclusion proof offline

```bash
python3 tools/verify_inclusion.py \
  --leaf 2e3aa189e1f666b2c3e864e21d978388020b89a6725e31ff2657bad5840a7f02 \
  --proof 70c2e612049c44d5947db6e3a8802a2050a16f0d303ac40ba294da811768a9eb \
  --index 0 --root 2c37c5cacd334ac863756947650e18cfab41f61b0cf84b28342489292060ba4f \
  --tree-size 2
```

→ `VALID`, exit code 0. Change `--index 0` to `--index 1` → `INVALID`, exit code 1. The script is
stdlib-only and implements the RFC 9162 §2.1.3.2 audit-path walk, including the `(fn, sn) == (0, 0)`
completeness check, so a proof that stops short of the root cannot pass.

### 3. Read the root straight off the chain, with no AOTrust code

```bash
python3 - <<'PY'
import json, base64, urllib.request
body = json.dumps({"jsonrpc":"2.0","id":1,"method":"query","params":{
    "request_type":"call_function","finality":"final","account_id":"notary-node.near",
    "method_name":"get_root","args_base64":base64.b64encode(b'{"seq":0}').decode()}}).encode()
r = json.load(urllib.request.urlopen(urllib.request.Request(
    "https://rpc.mainnet.near.org", data=body,
    headers={"Content-Type":"application/json"})))
print(bytes(r["result"]["result"]).decode())
PY
```

→ `"63a62462d8e65fe73b237c98885493099e7e783fbddfc3ede4f08c75e6ab0d58"` — the root stored for
`seq = 0`, returned JSON-serialised as a string of 64 hex characters. `get_root` on a sequence the
contract has not assigned yet returns `null`. `sequence()` returns how many roots are stored.

### 4. Run the exit kit against a log export

`export` reads a copy of the ledger database, so it is the operator's step; `verify` and `roots`
work on the resulting directory and are the steps a third party runs.

```bash
pip install pynacl
python3 tools/aotrust_export.py export --db /path/to/queue.db --out ./export
python3 tools/aotrust_export.py verify --dir ./export
python3 tools/aotrust_export.py roots  --dir ./export
python3 tools/aotrust_export.py roots  --dir ./export --rpc https://rpc.mainnet.near.org
```

→ four results, in order. The counts below come from one export of the production ledger; on your
own copy they are whatever your copy holds, and the check is the same:

```
exported: /path/to/export
  journal=231 anchors=33 leaves=231          # counts from your own ledger
receipts: ok=231 bad=0 without-pdr=0          # every PDR parses and carries a valid notary signature
roots: checked=33 mismatched=0 (leaves=231, anchors=33)   # every recorded root recomputes from leaves
on-chain root (notary-node.near): 079074f4…7865
  matches latest anchor #94: True             # the log is checked against the chain, not against us
```

`export` writes `journal.jsonl`, `anchors.jsonl`, `leaves.jsonl`, `MANIFEST.json` (SHA-256 of each
file, counts, PDR layout, notary public key) and a `README.md` explaining the directory. Delete the
vendor and that directory still verifies: signatures against the key in `MANIFEST.json`, inclusion
against a root that a NEAR transaction committed.

Exit codes are the interface: `0` = everything checked out, non-zero = something did not.

### 5. Verify in the browser

`verify/index.html` is a static page with no build step and no server side. Serve it and paste a
receipt:

```bash
python3 -m http.server 8000 --directory verify   # then open http://localhost:8000/
```

→ the page recomputes the SHA-256 in the browser, folds the Merkle proof to a root, and the
**Check against NEAR** button fetches `get_root` from a public RPC and shows whether the recomputed
root equals the on-chain one, with the root string and the anchor sequence on screen. The same page
is served at `verify.aotrust.link`, which additionally checks receipts on the server side.

### 6. Anchor once, by hand (optional, costs gas)

```bash
python3 scripts/anchor.py --leaves leaves.jsonl --send
```

→ `ANCHORED #<seq>: size=<n> root=<hex> tx=<hash>`, then a read-back of `get_root(<seq>)` from the
chain. The line is appended to `anchors.jsonl` only after that read-back matches; on mismatch the
script exits non-zero, prints the transaction hash, and records nothing.

## What NEAR does here

- **Hourly anchor.** A timer runs one anchor pass per hour. If new leaves exist since the last
  anchor, the job builds the Merkle root over *all* leaves so far — the tree is cumulative, so each
  anchor commits the whole log, not a window — and submits `anchor(root)` to `notary-node.near`.
  The production service runs this on an hourly systemd timer; `scripts/anchor.py` performs exactly
  one pass per invocation, so the cadence is whatever schedules it (cron, timer, or a human).
- **The Merkle root.** RFC 9162 hashing: leaf `SHA-256(0x00 || data)`, node
  `SHA-256(0x01 || left || right)`. The root is a 32-byte commitment to the leaf set and its order,
  so any single receipt can be proven included with a `log₂ n` audit path.
- **`get_root(seq)`.** A public view method: no key, no permission, no AOTrust dependency. Any NEAR
  RPC answers it, and the answer is signed by the network's consensus, not by us. That is the whole
  reason the root is on a chain instead of on our server.
- **Who can write.** Only the contract account itself: `anchor()` asserts
  `predecessor_account_id() == current_account_id()`, so a root can only be written by a transaction
  signed with a key on `notary-node.near`. There is no owner field, no admin list, no allowlist of
  writers, and no method that rewrites or deletes a stored root. Reads are permissionless; writes
  require the contract account's key.
- **What NEAR does not do here.** It does not validate the root's format — the contract stores the
  string it is given (the client sends 64 lowercase hex characters) — and it does not prove the leaf
  set is complete. Completeness is checked by recomputing the tree from `leaves.jsonl` and comparing
  it with the stored root, which is what `tools/aotrust_export.py roots` does. The chain supplies
  ordering, public availability and an independent copy of the commitment; it does not supply the
  leaves.

## Receipt format (PDR)

Exactly **239 bytes**: a 175-byte payload plus a 64-byte Ed25519 signature.

| offset | size | field | encoding |
|---|---|---|---|
| 0 | 1 | `version` | `0x03` (single-signer, current) or `0x04` (bilateral, legacy) |
| 1 | 1 | `sig_scheme` | `0x01` = Ed25519 |
| 2 | 1 | `payment_anchor_type` | `0x00` free, `0x05` base-USDC, `0x0a` Solana-USDC |
| 3 | 8 | `timestamp` | unix seconds, little-endian `u64` |
| 11 | 36 | `issuer` | UTF-8, NUL-padded (`notary-node.near`) |
| 47 | 32 | `subject_hash` | SHA-256 of the subject descriptor |
| 79 | 32 | `payload_hash` | SHA-256 of the notarised payload |
| 111 | 32 | `merkle_root` | root of the tree the receipt belongs to |
| 143 | 32 | `tx_hash` | NEAR anchor transaction hash, or zeroes |
| 175 | 64 | `signature` | Ed25519 over the NEP-413 envelope |

Struct layout for parsers: `"<BBBQ36s32s32s32s32s"` (175 bytes), then the signature.

The signature is not over the payload alone — it is over the NEP-413 envelope:
`struct.pack('<II', 2147484061, 175) + payload`. Verifying a receipt therefore needs the payload,
the signature and the notary public key
`490f51f23b993eacaff54fc977d9a7689ab7d4ae91504dc6cbdeadb2dbf1f462`
(also in each `MANIFEST.json`). Because `merkle_root` is inside the signed payload, a receipt cannot
be moved to another tree without breaking its signature.

## Baseline vs hackathon window

The hackathon window starts **19 October 2026**. The core of this project predates it, and the
README does not pretend otherwise.

| | before the window (baseline) | added in the window (from 2026-10-19) |
|---|---|---|
| NEAR anchor contract `notary-node.near` | deployed and anchoring since before the window; `anchor` / `get_root` / `sequence` unchanged | — |
| hourly anchor job | running in the production service against the SQLite ledger | `scripts/anchor.py`, a standalone port that reads `leaves.jsonl`, with dry run by default and no key path in the repo |
| receipts (PDR) | 239-byte format, Ed25519 over NEP-413, in production | — |
| Merkle log | RFC 9162, cumulative, in production | — |
| exit kit | — | `tools/aotrust_export.py`: `export` / `verify` / `roots`, plus the on-chain comparison of every recorded root |
| browser verification against the chain | — | `verify/`: static page that recomputes the hash, folds the proof and compares with `get_root` from a public RPC |
| this public repository | — | contract source, anchor script, verifiers, docs |

`tools/verify_inclusion.py` implements the RFC 9162 audit-path walk and existed before the window;
it is published here because the exit kit is useless without it.

## Build and deploy the contract

```bash
cd contract
cargo build --target wasm32-unknown-unknown --release
near deploy notary-node.near \
  target/wasm32-unknown-unknown/release/merkle_anchor.wasm \
  --initFunction new --initArgs '{}'
```

`contract/build/merkle_anchor.wasm` is a prebuilt artefact of `contract/src/lib.rs` (62 KB,
`opt-level="z"`, LTO, panic=abort) for reviewers without a Rust toolchain. See
[`contract/README.md`](contract/README.md) for the method list, access control and storage notes.

## Data formats

`leaves.jsonl` — one line per leaf, tree order is the `log_index` order:

```json
{"log_index": 0, "leaf": "4f04c3d7d6f9d2d8351404a2acbbdd2e18dda9ae0ff038d29a10952385680f43"}
```

`anchors.jsonl` — one line per accepted anchor, appended by `scripts/anchor.py --send`:

```json
{"anchor_seq": 0, "size": 3, "root": "84cbdbc2…", "near_tx": "<tx hash>", "ts": 1767225600, "account": "notary-node.near"}
```

Both files are plain JSONL: append-only, diffable, no schema registry, no database.

## Security

No key material lives in this repository, and none should. `scripts/anchor.py` reads
`NEAR_ACCOUNT_KEY` from the environment and prints a redacted plan, never the key. Receipt signature
verification uses only public keys. Reporting and scope: [`SECURITY.md`](SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE).

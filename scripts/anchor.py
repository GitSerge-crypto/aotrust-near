#!/usr/bin/env python3
"""anchor.py — anchor a Merkle root of leaves.jsonl into the NEAR contract.

What it does, in order:

  1. reads leaves from a JSONL file (one line per leaf, already hashed)
  2. builds an RFC 9162 Merkle tree over them and takes the root
  3. reads the contract sequence() with a read-only public RPC call
  4. prints exactly what it would submit — and stops

A transaction is sent only when --send is passed. On success one line is
appended to anchors.jsonl: {"anchor_seq", "size", "root", "near_tx", "ts"}.

Key material is read from the NEAR_ACCOUNT_KEY environment variable, holding
near-cli style credentials JSON:

    NEAR_ACCOUNT_KEY='{"account_id":"notary-node.near",
                       "public_key":"ed25519:...",
                       "secret_key":"ed25519:..."}'

No key is ever read from a file inside this repository, and no key is printed.

This is a standalone port of the production hourly anchor job. The production
job reads an SQLite ledger; this one reads leaves.jsonl, so it carries no
database schema, no service configuration and no operator key path.

Usage:
  python3 scripts/anchor.py --leaves examples/leaves.jsonl            # dry run
  python3 scripts/anchor.py --leaves leaves.jsonl --send              # real send
  python3 scripts/anchor.py --leaves leaves.jsonl --json              # machine output

Dependencies: Python 3.9+ for a dry run (stdlib only). `pip install py-near`
for --send. The dry run needs no network if --offline is passed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import urllib.request

DEFAULT_ACCOUNT = "notary-node.near"
DEFAULT_RPC = "https://rpc.mainnet.near.org"
ANCHOR_GAS = 30_000_000_000_000  # 30 Tgas: one LookupMap insert + assert
LEAF_BYTES = 32


# ─────────────────────────────── Merkle (RFC 9162) ──────────────────────────

def _hash_node(left: bytes, right: bytes) -> bytes:
    """RFC 9162 node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _mth(leaves: list[bytes]) -> bytes:
    """Merkle Tree Hash over already-hashed leaves (RFC 9162 §2.1.1).

    Leaves arriving here are final: they were produced with
    SHA-256(0x00 || data) before being written to leaves.jsonl, which is why
    they are returned unmodified for a single-leaf tree.
    """
    n = len(leaves)
    if n == 0:
        raise ValueError("empty leaf set")
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return _hash_node(_mth(leaves[:k]), _mth(leaves[k:]))


# ───────────────────────────────── input ────────────────────────────────────

def read_leaves(path: str) -> list[bytes]:
    """Read leaves.jsonl -> leaf hashes in tree order.

    Each line is {"log_index": <int>, "leaf": "<64 hex chars>"}. Lines are
    sorted by log_index, so file order does not matter. A duplicated or
    malformed index is a hard error: a tree built over an ambiguous ordering
    would produce a root nobody can reproduce.
    """
    leaves: list[tuple[int, bytes]] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: not JSON ({exc})") from exc
            try:
                idx = int(rec["log_index"])
                raw = bytes.fromhex(str(rec["leaf"]).strip().lower())
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{lineno}: needs log_index and hex leaf ({exc})") from exc
            if idx < 0:
                raise ValueError(f"{path}:{lineno}: negative log_index {idx}")
            if len(raw) != LEAF_BYTES:
                raise ValueError(
                    f"{path}:{lineno}: leaf is {len(raw)} bytes, expected {LEAF_BYTES}")
            leaves.append((idx, raw))

    if not leaves:
        raise ValueError(f"{path}: no leaves")
    leaves.sort(key=lambda pair: pair[0])
    for prev, cur in zip(leaves, leaves[1:]):
        if prev[0] == cur[0]:
            raise ValueError(f"{path}: duplicated log_index {cur[0]}")
    return [leaf for _, leaf in leaves]


def read_anchors(path: str) -> list[dict]:
    """Read anchors.jsonl (append-only history this script writes)."""
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


# ───────────────────────────────── chain reads ──────────────────────────────

def _view(rpc: str, account: str, method: str, args: dict, timeout: float = 20.0) -> bytes:
    """Read-only contract call through a public NEAR RPC (no key, no signature)."""
    body = json.dumps({
        "jsonrpc": "2.0", "id": "anchor.py", "method": "query",
        "params": {
            "request_type": "call_function",
            "finality": "final",
            "account_id": account,
            "method_name": method,
            "args_base64": base64.b64encode(json.dumps(args).encode()).decode(),
        },
    }).encode()
    req = urllib.request.Request(
        rpc, data=body, headers={"Content-Type": "application/json"})
    payload = json.load(urllib.request.urlopen(req, timeout=timeout))["result"]
    if payload.get("error"):
        raise RuntimeError(payload["error"])
    return bytes(payload["result"])


def get_sequence(rpc: str, account: str) -> int | None:
    """sequence() -> number of roots stored so far, i.e. the next anchor_seq.

    None means the RPC did not answer; a dry run then reports the sequence as
    unknown instead of guessing it.
    """
    try:
        return int(json.loads(_view(rpc, account, "sequence", {}).decode().strip()))
    except Exception:
        return None


def get_root(rpc: str, account: str, seq: int) -> str | None:
    """get_root(seq) -> the stored root as 64 hex chars, or None if seq is unset."""
    raw = _view(rpc, account, "get_root", {"seq": int(seq)}).decode().strip()
    if not raw or raw == "null":
        return None
    value = json.loads(raw)
    if value is None:
        return None
    text = str(value).strip().strip('"').lower()
    return text or None


# ──────────────────────────────── sending ───────────────────────────────────

async def _close_account(account) -> None:
    """Best-effort close of the aiohttp session held by py_near."""
    try:
        provider = getattr(account, "_provider", None)
        client = getattr(provider, "_client", None)
        connector = getattr(provider, "_connector", None)
        if client is not None and not client.closed:
            await client.close()
        if connector is not None and not connector.closed:
            await connector.close()
    except Exception:
        pass


def _extract_anchor_result(result) -> tuple[str, int]:
    """Return (tx_hash, assigned_seq) from the anchor transaction outcome.

    The contract returns u64, which NEAR JSON-serialises into SuccessValue:
    base64 of b"97", not 8 raw bytes.
    """
    tx = ""
    transaction = getattr(result, "transaction", None)
    if transaction is not None:
        tx = getattr(transaction, "hash", "") or ""
    if not tx:
        outcome = getattr(result, "transaction_outcome", None)
        if isinstance(outcome, dict):
            tx = outcome.get("id", "") or ""
    status = getattr(result, "status", None)
    if not isinstance(status, dict):
        raise RuntimeError(f"ANCHOR_TX_FAILED | tx={tx or 'unknown'} status={status}")
    if "SuccessValue" not in status:
        raise RuntimeError(f"ANCHOR_TX_FAILED | tx={tx or 'unknown'} status={status}")
    raw = base64.b64decode(status["SuccessValue"] or "")
    if not raw:
        raise RuntimeError(
            f"ANCHOR_TX_FAILED | tx={tx or 'unknown'} status=empty SuccessValue "
            f"(check the transaction; the anchor may still have landed)")
    try:
        seq = int(json.loads(raw.decode("utf-8")))
    except Exception:
        if len(raw) == 8:
            seq = int.from_bytes(raw, "little")
        else:
            raise RuntimeError(
                f"ANCHOR_TX_FAILED | tx={tx or 'unknown'} "
                f"unparseable SuccessValue raw={raw[:16].hex()}")
    if not (0 <= seq < 2 ** 64):
        raise RuntimeError(f"ANCHOR_TX_FAILED | tx={tx or 'unknown'} seq={seq} out of range")
    return tx, int(seq)


async def _send_anchor(rpc: str, account_id: str, private_key: str,
                       root_hex: str) -> tuple[str, int]:
    """Submit anchor(root) and return (tx_hash, anchor_seq)."""
    try:
        from py_near.account import Account
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise SystemExit(
            "--send needs the py-near package: pip install py-near") from exc

    account = Account(account_id, private_key, rpc_addr=rpc)
    try:
        await account.startup()
        result = await account.function_call(
            account_id, "anchor", {"root": root_hex},
            gas=ANCHOR_GAS, included=False)
        return _extract_anchor_result(result)
    finally:
        await _close_account(account)


# ───────────────────────────────── key ──────────────────────────────────────

def load_key_from_env() -> tuple[str | None, str]:
    """Parse NEAR_ACCOUNT_KEY (near-cli credentials JSON, or a bare secret key).

    Returns (account_id_from_blob_or_None, secret_key). Never logs the key.
    """
    blob = os.environ.get("NEAR_ACCOUNT_KEY", "").strip()
    if not blob:
        raise SystemExit(
            "NEAR_ACCOUNT_KEY is not set. Export near-cli style credentials:\n"
            "  export NEAR_ACCOUNT_KEY='{\"account_id\":\"notary-node.near\","
            "\"secret_key\":\"ed25519:...\"}'")
    if blob.startswith("{"):
        try:
            data = json.loads(blob)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"NEAR_ACCOUNT_KEY is not valid JSON: {exc}") from exc
        key = data.get("secret_key") or data.get("private_key") or ""
        if not key:
            raise SystemExit("NEAR_ACCOUNT_KEY has no secret_key/private_key field")
        return data.get("account_id"), key.strip()
    return None, blob


# ───────────────────────────────── main ─────────────────────────────────────

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="anchor.py",
        description="Anchor a Merkle root of leaves.jsonl into a NEAR contract "
                    "(dry run by default).")
    ap.add_argument("--leaves", default="leaves.jsonl",
                    help="leaf file, JSONL: {\"log_index\":int,\"leaf\":\"hex\"} "
                         "(default leaves.jsonl)")
    ap.add_argument("--anchors", default="anchors.jsonl",
                    help="append-only anchor history written on --send "
                         "(default anchors.jsonl)")
    ap.add_argument("--account", default=os.environ.get("NEAR_ACCOUNT_ID", DEFAULT_ACCOUNT),
                    help=f"contract account (default {DEFAULT_ACCOUNT})")
    ap.add_argument("--rpc", default=os.environ.get("NEAR_RPC_URL", DEFAULT_RPC),
                    help=f"NEAR RPC endpoint (default {DEFAULT_RPC})")
    ap.add_argument("--send", action="store_true",
                    help="actually submit the transaction (default: print only)")
    ap.add_argument("--dry-run", action="store_true",
                    help="explicit no-op flag; dry run is already the default")
    ap.add_argument("--offline", action="store_true",
                    help="skip the sequence() read (no network at all)")
    ap.add_argument("--force", action="store_true",
                    help="anchor even if the last recorded anchor has this size and root")
    ap.add_argument("--json", action="store_true",
                    help="print one JSON object instead of human lines")
    args = ap.parse_args(argv)

    send = args.send and not args.dry_run

    try:
        leaves = read_leaves(args.leaves)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    root_hex = _mth(leaves).hex()
    size = len(leaves)

    history = read_anchors(args.anchors)
    last = history[-1] if history else None
    if last is not None and int(last.get("size", -1)) > size:
        print(f"error: {args.anchors} records size={last.get('size')}, "
              f"but {args.leaves} has only {size} leaves; the log shrank",
              file=sys.stderr)
        return 3

    unchanged = (last is not None
                 and int(last.get("size", -1)) == size
                 and str(last.get("root", "")).lower() == root_hex)
    if unchanged and not args.force:
        record = {
            "status": "already_anchored", "size": size, "root": root_hex,
            "anchor_seq": last.get("anchor_seq"), "near_tx": last.get("near_tx"),
        }
        if args.json:
            print(json.dumps(record))
        else:
            print(f"leaves: {size}, root: {root_hex}")
            print(f"nothing new: anchor #{last.get('anchor_seq')} already commits "
                  f"this size and root ({last.get('near_tx')})")
        return 0

    chain_seq = None if args.offline else get_sequence(args.rpc, args.account)
    next_seq = chain_seq if chain_seq is not None else "unknown"

    if args.json and not send:
        print(json.dumps({
            "status": "dry_run", "size": size, "root": root_hex,
            "contract": args.account, "rpc": args.rpc,
            "chain_sequence": chain_seq, "would_call": "anchor",
            "would_send": False,
        }))
        return 0
    if not args.json:
        print(f"leaves: {size} (sorted by log_index, RFC 9162)")
        print(f"merkle root: {root_hex}")
        print(f"tree size: {size}")
        print(f"contract: {args.account} @ {args.rpc}")
        if args.offline:
            print("chain sequence: skipped (--offline)")
        elif chain_seq is None:
            print("chain sequence: unavailable (RPC did not answer)")
        else:
            print(f"chain sequence: {chain_seq} -> anchor_seq {chain_seq}")

    if not send:
        if not args.json:
            print(f'DRY RUN: would call anchor("{root_hex}") on {args.account} '
                  f'(gas {ANCHOR_GAS // 10**12} Tgas)')
            print(f"DRY RUN: anchor_seq would be {next_seq} "
                  f"(assigned by the contract, not by this script)")
            print(f"DRY RUN: no transaction sent, {args.anchors} untouched")
            print("to send for real: export NEAR_ACCOUNT_KEY=... then add --send")
        return 0

    # ── real send ──
    account_from_key, private_key = load_key_from_env()
    if account_from_key and account_from_key != args.account:
        print(f"error: NEAR_ACCOUNT_KEY is for {account_from_key}, "
              f"but --account is {args.account}", file=sys.stderr)
        return 2

    import asyncio
    try:
        tx, seq = asyncio.run(_send_anchor(args.rpc, args.account, private_key, root_hex))
    except SystemExit:
        raise
    except Exception as exc:
        print(f"error: anchor transaction failed: {exc}", file=sys.stderr)
        return 4

    # Read back what the chain now stores for this seq; do not trust the receipt
    # of our own transaction when the chain can be asked directly.
    confirmed = None
    try:
        confirmed = get_root(args.rpc, args.account, seq)
    except Exception:
        confirmed = None

    if confirmed is not None and confirmed.lower() != root_hex:
        print(f"error: on-chain get_root({seq}) = {confirmed}, expected {root_hex}; "
              f"tx={tx}. Not recorded in {args.anchors}.", file=sys.stderr)
        return 5

    record = {
        "anchor_seq": int(seq),
        "size": size,
        "root": root_hex,
        "near_tx": tx,
        "ts": int(time.time()),
        "account": args.account,
    }
    with open(args.anchors, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

    if args.json:
        print(json.dumps({"status": "anchored", **record,
                          "chain_confirmed": confirmed is not None}))
    else:
        print(f"ANCHORED #{seq}: size={size} root={root_hex} tx={tx}")
        print(f"on-chain confirmation: "
              f"{'get_root(' + str(seq) + ') matches' if confirmed else 'not read (RPC)'}")
        print(f"appended: {args.anchors}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

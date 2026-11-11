#!/usr/bin/env python3
"""aotrust_export.py — AOTrust exit kit.

Three subcommands:

  export   dump the full journal, anchors and leaves into a directory (JSONL + MANIFEST)
  verify   check receipts offline: PDR v0x03/v0x04 structure + notary signature
  roots    recompute Merkle roots from the leaves and compare them with the recorded
           anchors (optionally with the root stored in the NEAR contract, over any
           public RPC)

Nothing here talks to the AOTrust service: export reads a copy of the SQLite ledger
directly, verify and roots work only on an exported directory. The single network
operation is the optional `roots --rpc URL`.

Dependencies: Python 3.9+, PyNaCl (`pip install pynacl`) — signature checks only.

Example:
  python3 tools/aotrust_export.py export --db /path/to/queue.db --out /tmp/export
  python3 tools/aotrust_export.py verify --dir /tmp/export
  python3 tools/aotrust_export.py roots  --dir /tmp/export --rpc https://rpc.mainnet.near.org
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import struct
import sys
import urllib.request

NEP413_TAG = 2147484061  # 2^31 + 413
EXT_PAYLOAD_LEN = 175     # BBBQ36s32s32s32s32s
PDR_TOTAL_LEN = 239       # payload + 64-byte Ed25519 signature
PDR_V3 = 0x03
PDR_V4 = 0x04
PAT_NAMES = {0x00: "free", 0x05: "base-usdc", 0x0A: "solana-usdc"}


# ─────────────────────────────── PDR ────────────────────────────────────────

def parse_pdr(raw: bytes) -> dict:
    if len(raw) not in (PDR_TOTAL_LEN,):
        raise ValueError(f"PDR length {len(raw)}, expected {PDR_TOTAL_LEN}")
    payload, signature = raw[:EXT_PAYLOAD_LEN], raw[EXT_PAYLOAD_LEN:]
    (version, sig_scheme, pat, ts_sec, issuer,
     subject_hash, payload_hash, merkle_root, tx_hash) = struct.unpack(
        "<BBBQ36s32s32s32s32s", payload)
    return {
        "version": version,
        "sig_scheme": sig_scheme,
        "payment_anchor_type": pat,
        "timestamp_utc": ts_sec,
        "issuer": issuer.rstrip(b"\x00").decode("utf-8", "replace"),
        "subject_hash": subject_hash.hex(),
        "payload_hash": payload_hash.hex(),
        "merkle_root": merkle_root.hex(),
        "tx_hash": tx_hash.hex(),
        "signature": signature,
        "payload": payload,
        "raw": raw,
    }


def verify_signature(pdr: dict, pubkey_hex: str) -> bool:
    from nacl.signing import VerifyKey
    envelope = struct.pack("<II", NEP413_TAG, EXT_PAYLOAD_LEN) + pdr["payload"]
    try:
        VerifyKey(bytes.fromhex(pubkey_hex)).verify(envelope, pdr["signature"])
        return True
    except Exception:
        return False


# ────────────────────────────── export ──────────────────────────────────────

def cmd_export(args) -> int:
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    conn = sqlite3.connect(f"file:{os.path.abspath(args.db)}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    journal_path = os.path.join(out, "journal.jsonl")
    with open(journal_path, "w", encoding="utf-8") as fh:
        for row in conn.execute(
                "SELECT global_seq, created_at, work_hash, payment_anchor_type,"
                " payer_address, external_pdr, source FROM notary_ledger"
                " ORDER BY global_seq"):
            pdr = row["external_pdr"]
            fh.write(json.dumps({
                "seq": row["global_seq"],
                "created_at_ns": row["created_at"],
                "work_hash": row["work_hash"],
                "payment_anchor_type": row["payment_anchor_type"],
                "payer_address": row["payer_address"],
                "source": row["source"],
                "pdr_b64": base64.b64encode(pdr).decode() if pdr else None,
            }, ensure_ascii=False) + "\n")

    anchors_path = os.path.join(out, "anchors.jsonl")
    with open(anchors_path, "w", encoding="utf-8") as fh:
        for row in conn.execute(
                "SELECT anchor_seq, size, root, near_tx, ts, cumulative"
                " FROM anchor_history ORDER BY anchor_seq"):
            fh.write(json.dumps({
                "anchor_seq": row["anchor_seq"],
                "size": row["size"],
                "root": row["root"].hex() if isinstance(row["root"], (bytes, bytearray)) else row["root"],
                "near_tx": row["near_tx"],
                "ts": row["ts"],
                "cumulative": row["cumulative"],
            }) + "\n")

    leaves_path = os.path.join(out, "leaves.jsonl")
    with open(leaves_path, "w", encoding="utf-8") as fh:
        # Leaf order = tree order: anchor_log.log_index (not global_seq:
        # time-attestation/snapshot leaves land in the same log with their own kind).
        for row in conn.execute("SELECT log_index, kind, ref_id, leaf FROM anchor_log ORDER BY log_index"):
            leaf = row["leaf"]
            fh.write(json.dumps({
                "log_index": row["log_index"],
                "kind": row["kind"],
                "ref_id": row["ref_id"],
                "leaf": leaf.hex() if isinstance(leaf, (bytes, bytearray)) else leaf,
            }) + "\n")

    counts = {
        "journal": sum(1 for _ in open(journal_path, encoding="utf-8")),
        "anchors": sum(1 for _ in open(anchors_path, encoding="utf-8")),
        "leaves": sum(1 for _ in open(leaves_path, encoding="utf-8")),
    }
    manifest = {
        "exported_at_utc": _utc_now(),
        "source": os.path.abspath(args.db),
        "notary_pubkey_hex": args.pubkey,
        "issuer": args.issuer,
        "counts": counts,
        "files": {name: _sha256_file(os.path.join(out, name))
                  for name in ("journal.jsonl", "anchors.jsonl", "leaves.jsonl")},
        "format": {
            "pdr_bytes": PDR_TOTAL_LEN,
            "pdr_payload_bytes": EXT_PAYLOAD_LEN,
            "payload_layout": "version:B sig_scheme:B payment_anchor_type:B "
                              "timestamp:Q issuer:36s subject_hash:32s payload_hash:32s "
                              "merkle_root:32s tx_hash:32s",
            "signature": "Ed25519 over NEP-413 envelope: LE u32 tag=2147484061, LE u32 len=175, payload",
            "merkle": "RFC 9162: leaf=SHA256(0x00||slice), node=SHA256(0x01||left||right)",
        },
    }
    with open(os.path.join(out, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)

    with open(os.path.join(out, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(EXIT_README.format(**counts))

    print(f"exported: {out}")
    print(f"  journal={counts['journal']} anchors={counts['anchors']} leaves={counts['leaves']}")
    print(f"  manifest: {os.path.join(out, 'MANIFEST.json')}")
    return 0


EXIT_README = """# AOTrust exit kit — how to verify without us

This directory is a complete, self-contained copy of the AOTrust append-only log.
It was exported directly from the ledger database, not from the service.

## What is here

| file | content |
|---|---|
| `journal.jsonl` | one line per record: {journal} records, each with the 239-byte PDR (base64) |
| `anchors.jsonl` | one line per NEAR anchor: {anchors} anchors (size, Merkle root, NEAR tx) |
| `leaves.jsonl` | one line per Merkle leaf: {leaves} leaves |
| `MANIFEST.json` | SHA-256 of each file, counts, PDR layout, notary public key |

## Verify a receipt without AOTrust

```bash
pip install pynacl
python3 tools/aotrust_export.py verify --dir .   # structure + notary signature on every PDR
```

## Verify the log itself without AOTrust

```bash
python3 tools/aotrust_export.py roots --dir . --rpc https://rpc.mainnet.near.org
```

This recomputes every anchor root from `leaves.jsonl` (RFC 9162) and compares it with
`anchors.jsonl`. With `--rpc`, it additionally reads `get_root` from the NEAR contract
`notary-node.near` and compares it with the latest anchor — i.e. the log is checked
against the chain, not against our word.

## If AOTrust disappears

1. This directory keeps every receipt: hashes, timestamps, signatures, anchor transaction ids.
2. Receipts stay verifiable forever: signature → notary public key in `MANIFEST.json`;
   inclusion → Merkle root from `anchors.jsonl` → transaction on NEAR.
3. To continue the log elsewhere, any party can start a new Merkle log and re-anchor
   these leaves; nothing in the format depends on our servers.
"""


# ────────────────────────────── verify ──────────────────────────────────────

def cmd_verify(args) -> int:
    d = os.path.abspath(args.dir)
    manifest = json.load(open(os.path.join(d, "MANIFEST.json"), encoding="utf-8"))
    pubkey = manifest["notary_pubkey_hex"]

    ok = bad = skipped = 0
    failures = []
    for line in open(os.path.join(d, "journal.jsonl"), encoding="utf-8"):
        rec = json.loads(line)
        if not rec.get("pdr_b64"):
            skipped += 1
            continue
        try:
            pdr = parse_pdr(base64.b64decode(rec["pdr_b64"]))
        except Exception as exc:
            bad += 1
            failures.append((rec["seq"], f"parse: {exc}"))
            continue
        if pdr["version"] not in (PDR_V3, PDR_V4):
            bad += 1
            failures.append((rec["seq"], f"unknown version 0x{pdr['version']:02x}"))
            continue
        if not verify_signature(pdr, pubkey):
            bad += 1
            failures.append((rec["seq"], "bad notary signature"))
            continue
        if pdr["version"] == PDR_V3 and pdr["payload_hash"] != rec["work_hash"]:
            bad += 1
            failures.append((rec["seq"], "payload_hash != work_hash for v0x03"))
            continue
        ok += 1

    print(f"receipts: ok={ok} bad={bad} without-pdr={skipped}")
    for seq, why in failures[:10]:
        print(f"  seq {seq}: {why}")
    return 0 if bad == 0 else 1


# ────────────────────────────── roots ───────────────────────────────────────

def _hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _mth(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return _hash_node(_mth(leaves[:k]), _mth(leaves[k:]))


def cmd_roots(args) -> int:
    d = os.path.abspath(args.dir)
    leaves = [bytes.fromhex(json.loads(l)["leaf"])
              for l in open(os.path.join(d, "leaves.jsonl"), encoding="utf-8")]
    anchors = [json.loads(l) for l in open(os.path.join(d, "anchors.jsonl"), encoding="utf-8")]
    bad = 0
    checked = 0
    for a in anchors:
        size = int(a["size"])
        if size <= 0 or size > len(leaves):
            continue
        root = _mth(leaves[:size]).hex()
        checked += 1
        if root != a["root"]:
            bad += 1
            print(f"  anchor #{a['anchor_seq']}: root mismatch (computed {root[:16]}… vs {a['root'][:16]}…)")
    print(f"roots: checked={checked} mismatched={bad} (leaves={len(leaves)}, anchors={len(anchors)})")

    if args.rpc:
        last = anchors[-1]
        try:
            on_chain = _near_get_root(args.rpc, args.account, int(last["anchor_seq"]))
            same = on_chain and on_chain.lower() == last["root"].lower()
            print(f"on-chain root ({args.account}): {on_chain}")
            print(f"  matches latest anchor #{last['anchor_seq']}: {same}")
            if not same:
                bad += 1
        except Exception as exc:
            print(f"  RPC check failed: {exc}")
    return 0 if bad == 0 else 1


def _near_get_root(rpc: str, account: str, seq: int) -> str:
    body = json.dumps({
        "jsonrpc": "2.0", "id": "exit-kit", "method": "query",
        "params": {"request_type": "call_function", "finality": "final",
                   "account_id": account, "method_name": "get_root",
                   "args_base64": base64.b64encode(json.dumps({"seq": int(seq)}).encode()).decode()},
    }).encode()
    req = urllib.request.Request(rpc, data=body, headers={"Content-Type": "application/json"})
    payload = json.load(urllib.request.urlopen(req, timeout=20))["result"]
    if payload.get("error"):
        raise RuntimeError(payload["error"])
    res = payload
    raw = bytes(res["result"])
    # get_root may return 32 raw bytes or a JSON/base64 string; handle both
    if len(raw) == 32:
        return raw.hex()
    text = raw.decode("utf-8", "replace").strip().strip('"')
    if len(text) == 64:
        return text
    try:
        return json.loads(text)["root"].lower()
    except Exception:
        return text


# ─────────────────────────────── helpers ────────────────────────────────────

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _utc_now() -> str:
    import datetime
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="aotrust-export", description="AOTrust exit kit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("export", help="dump journal, anchors and leaves")
    e.add_argument("--db", required=True)
    e.add_argument("--out", required=True)
    e.add_argument("--pubkey", default="490f51f23b993eacaff54fc977d9a7689ab7d4ae91504dc6cbdeadb2dbf1f462")
    e.add_argument("--issuer", default="notary-node.near")
    e.set_defaults(func=cmd_export)

    v = sub.add_parser("verify", help="offline receipt checks")
    v.add_argument("--dir", required=True)
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("roots", help="recompute Merkle roots")
    r.add_argument("--dir", required=True)
    r.add_argument("--rpc", default=None)
    r.add_argument("--account", default="notary-node.near")
    r.set_defaults(func=cmd_roots)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

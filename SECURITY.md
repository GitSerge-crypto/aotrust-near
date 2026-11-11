# Security Policy

## Reporting a vulnerability

Email **legal@aotrust.link** with the subject `Security Vulnerability — aotrust-near`.
Include what you found, how to reproduce it, and the impact you expect.

Machine-readable policy: `https://docs.aotrust.link/.well-known/security.txt`.

## What we commit to

- Acknowledgement within 3 business days, assessment within 10.
- An honest answer about whether and when we can fix it. There is no bounty programme — we say so
  rather than imply one.
- No action against good-faith researchers; coordinated disclosure within 90 days, or sooner after
  a fix ships.

## In scope

This repository:

- the anchor contract `notary-node.near` and its source in `contract/` — access control, state
  growth, transaction handling;
- `scripts/anchor.py` — leaf handling, Merkle root computation, key handling, what it writes to
  `anchors.jsonl`;
- `tools/aotrust_export.py` — export, offline receipt verification, root recomputation, RPC parsing;
- `tools/verify_inclusion.py` — the RFC 9162 audit-path walk, including proof-completeness checks;
- `verify/` — the static browser verifier;
- the PDR receipt format (239 bytes: 175-byte payload + 64-byte Ed25519 signature over the NEP-413
  envelope).

Production surfaces are documented separately: `api.aotrust.link`, the static hosts, and the client
packages.

## Out of scope

Physical access to the operator's machine, compromised wallets or keys, social engineering, spam and
volumetric DoS, and scanner output without a reproduction.

## Keys and key handling

- No key material is stored in this repository, and none may be committed. `scripts/anchor.py` reads
  `NEAR_ACCOUNT_KEY` from the environment only, and never prints it.
- The notary signing key is held in memory by the production service; the seed is supplied at
  start-up. Rotations are published in the transparency log and at
  `https://api.aotrust.link/v1/notary/pubkey`.
- Receipt verification needs no secret at all: the notary public key is published here, in every
  export's `MANIFEST.json`, and at the endpoint above.

## Continuity

If this service disappears, receipts stay verifiable: signature against the published public key,
inclusion against a Merkle root that a NEAR transaction committed. The exit kit documents the
procedure for whoever ends up holding the receipts — that is the point of shipping it.

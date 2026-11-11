/* AOTrust receipt verifier — no vendor in the path.
 * Pure browser: 239-byte PDR parser, Ed25519 check (WebCrypto, @noble fallback),
 * RFC 9162 inclusion fold, NEAR RPC read of get_root(seq).
 */

'use strict';

/* ---------------------------------------------------------------- constants */

// notary-node.near public key (Ed25519), also served at /.well-known/jwks.json
const NOTARY_PUBKEY_HEX =
  '490f51f23b993eacaff54fc977d9a7689ab7d4ae91504dc6cbdeadb2dbf1f462';

const PDR_TOTAL_LEN = 239;   // full receipt
const PDR_PAYLOAD_LEN = 175; // bytes covered by the signature
const NEP413_TAG = 2147484061; // 0x800000DD — "signed message" discriminator
const NEAR_RPC = 'https://rpc.mainnet.near.org';
const CONTRACT = 'notary-node.near';

// Field layout of the 239-byte PDR v3, in order.
const LAYOUT = [
  { key: 'version',             off: 0,   len: 1,  label: 'version' },
  { key: 'sig_scheme',          off: 1,   len: 1,  label: 'signature scheme' },
  { key: 'payment_anchor_type', off: 2,   len: 1,  label: 'payment anchor type' },
  { key: 'timestamp',           off: 3,   len: 8,  label: 'timestamp (u64 LE)' },
  { key: 'issuer',              off: 11,  len: 36, label: 'issuer' },
  { key: 'subject_hash',        off: 47,  len: 32, label: 'subject hash' },
  { key: 'payload_hash',        off: 79,  len: 32, label: 'file SHA-256 (payload_hash)' },
  { key: 'merkle_root',         off: 111, len: 32, label: 'merkle root (in-receipt)' },
  { key: 'tx_hash',             off: 143, len: 32, label: 'tx hash' },
  { key: 'signature',           off: 175, len: 64, label: 'signature (Ed25519)' }
];

const SIG_SCHEMES = { 1: '1 · Ed25519' };
const PAYMENT_TYPES = {
  0: '0 · unpaid (free)',
  1: '1 · Base USDC (x402)',
  2: '2 · NEAR native',
  3: '3 · USDC transfer claim',
  4: '4 · partner rail',
  5: '5 · cumulative anchor'
};

/* Examples. Each entry is a real 239-byte receipt plus, where published, the
 * RFC 9162 inclusion path for it (leaf hash, index, tree size, audit path) taken
 * from the public anchor log. The path is data, not trust: the root it folds to
 * is compared against notary-node.near on the button press. */
const EXAMPLES = [
  {
    "label": "anchored \u00b7 anchor 94",
    "pdr_b64": "AwEFA6L0agAAAABub3Rhcnktbm9kZS5uZWFyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP2IXYc7qTouh+piEViiyGYJ63YdLJTxvJMoZdhJtF82AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADueh04v6jfyIpVyWbfCPactDGhYlr1GjsgbRSRLjXFG/8gvweFq/RBFq5V4vW98DJsOiExZuc9S+WlOehBKVG8o795xK5+6gQWoX6zl5TS7D7z0gK9fQ8K4d14lYgblAk=",
    "note": "Real receipt, ledger record 230 \u2014 the last leaf of the tree anchored at seq 94. Its published inclusion path is bundled, so the root is folded in this tab.",
    "leaf": "1498211e1c9ce82eae7dcff76a49f330efb8b0b8dd213a8883cfc6a7273b5514",
    "index": 235,
    "size": 236,
    "path": [
      "4e12e425aa895028eef2beb6ef5ec9cc30f2dfb49db1ddb167f7028d630c9fac",
      "74da7fa1f64d04e1b0fcfcd64988ef2398325e7dc87dc1064f42b408260d7f8d",
      "ae21215ff42f151cb710d4791a54daa0d4edd1cd367c217ab1c2d1d763019256",
      "afbce9df3b933040941d06b1d957aadd53664344fa8aaf0db60b5f0970c54772",
      "c1a44c23563d9b15bc5813fd994f9775ad1fe4ceb3524eeeb84fd8c8bdeddf2d",
      "fb5de336a99a01dc0951c25cfba642c894ba25886f76b9d0cf5418bbc8aa0858"
    ],
    "anchor_seq": 94
  },
  {
    "label": "shield 91ce7b66",
    "pdr_b64": "AwEA7cT0agAAAABub3Rhcnktbm9kZS5uZWFyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALl11lm/ECxm3lxob99z10UEfHe+mqPiOvzd0tBHrhvMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEqcN0IpH3lwTPc74wxPaAtbI0oasp9ypnnivpc7/Pa6v+HKfQBS4XcW/IJTFr3ED7titGfZ4qNAvJd2KnCaYQM=",
    "note": "Real receipt from the public log (shield 91ce7b66, 2026-11-11 19:41:33Z). Free record: no anchor root committed, so the chain check has nothing to compare.",
    "anchor_seq": 94
  },
  {
    "label": "shield 266e9612",
    "pdr_b64": "AwEA6cv0agAAAABub3Rhcnktbm9kZS5uZWFyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeK54EoibFcCH2VEZu8k/W91wH9ZFbe2ugnhCfXqh2DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANn//bPUHfDxUbfA+LqIRXAHiDI4S8NOAot2PHvAaLrXMhAbmNKrqnBpV0CbhX7ZlVK1KUbcT2WGaGj6ujAVMwg=",
    "note": "Real receipt from the public log (shield 266e9612, 2026-11-11 20:11:21Z). Free record: no anchor root committed, so the chain check has nothing to compare.",
    "anchor_seq": 94
  }
];

/* ------------------------------------------------------------------ helpers */

const $ = (id) => document.getElementById(id);

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

function toHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += HEX[bytes[i]];
  return s;
}

function fromHex(hex) {
  const clean = hex.trim().replace(/^0x/i, '').replace(/\s+/g, '');
  if (clean.length % 2 || /[^0-9a-fA-F]/.test(clean)) throw new Error('not valid hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function utf8(str) { return new TextEncoder().encode(str); }

function isZero(bytes) {
  for (let i = 0; i < bytes.length; i++) if (bytes[i] !== 0) return false;
  return true;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/* Accepts base64 (standard or URL-safe, padding optional) or hex. */
function decodeReceipt(raw) {
  const text = raw.trim();
  if (!text) throw new Error('nothing pasted');

  const hexish = text.replace(/^0x/i, '').replace(/[\s,:-]/g, '');
  if (/^[0-9a-fA-F]+$/.test(hexish) && hexish.length >= 64) {
    return { bytes: fromHex(hexish), how: 'hex' };
  }

  let b64 = decodeURIComponent(text).replace(/\s+/g, '')
    .replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  let bin;
  try {
    bin = atob(b64);
  } catch (e) {
    throw new Error('not valid base64 or hex');
  }
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return { bytes, how: 'base64' };
}

function parsePdr(pdr) {
  const out = { raw: pdr };
  for (const f of LAYOUT) out[f.key] = pdr.slice(f.off, f.off + f.len);
  // u64 LE timestamp
  let ts = 0n;
  for (let i = 7; i >= 0; i--) ts = (ts << 8n) | BigInt(out.timestamp[i]);
  out.ts = Number(ts);
  out.tsIso = new Date(out.ts * 1000).toISOString().replace('.000Z', 'Z');
  out.issuerText = new TextDecoder().decode(out.issuer).replace(/\u0000+$/, '').trim();
  // signed envelope: u32LE(tag) ‖ u32LE(payload len) ‖ payload
  const head = new Uint8Array(8);
  const dv = new DataView(head.buffer);
  dv.setUint32(0, NEP413_TAG, true);
  dv.setUint32(4, PDR_PAYLOAD_LEN, true);
  out.envelope = concat(head, pdr.slice(0, PDR_PAYLOAD_LEN));
  return out;
}

/* --------------------------------------------------------------- statuses */

function setPlate(id, state, verdict, detail) {
  const el = $(id);
  el.className = 'plate ' + state;
  el.querySelector('.pverdict').textContent = verdict;
  el.querySelector('.pdetail').textContent = detail;
}

/* ------------------------------------------------------------ Ed25519 */

let ed25519Method = null; // 'webcrypto' | 'noble' | null

async function ed25519Verify(sig, msg, pub) {
  // 1) native WebCrypto (Chrome 137+, Safari 17+, Firefox 129+)
  try {
    const key = await crypto.subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
    const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, sig, msg);
    ed25519Method = 'webcrypto';
    return { ok, method: 'WebCrypto Ed25519 (browser native)' };
  } catch (e) {
    /* fall through */
  }
  // 2) @noble/ed25519 from esm.sh (async API — v2 sync verify needs a hash hook)
  try {
    const ed = await import('https://esm.sh/@noble/ed25519@2.3.0');
    const runner = ed.verifyAsync || ed.verify;
    const ok = await runner(sig, msg, pub);
    ed25519Method = 'noble';
    return { ok, method: '@noble/ed25519 (fallback, loaded from esm.sh)' };
  } catch (e) {
    ed25519Method = null;
    return { ok: null, method: 'unavailable', error: e.message };
  }
}

/* ------------------------------------------------ RFC 9162 inclusion fold */

function hashNode(left, right) {
  return sha256(concat(new Uint8Array([0x01]), left, right));
}

async function foldPath(leafHash, index, treeSize, path) {
  let fn = index;
  let sn = treeSize - 1;
  let r = leafHash;
  for (const p of path) {
    if (sn === 0) throw new Error('proof longer than the tree allows');
    if ((fn & 1) === 1 || fn === sn) {
      r = await hashNode(p, r);
      while (fn !== 0 && (fn & 1) === 0) { fn >>= 1; sn >>= 1; }
    } else {
      r = await hashNode(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  if (fn !== 0 || sn !== 0) throw new Error('proof does not close the tree (tree size mismatch)');
  return r;
}

/* ------------------------------------------------------------- NEAR read */

function rootFromRpcResult(result) {
  if (!result || !Array.isArray(result.result)) {
    throw new Error('no result bytes in RPC response');
  }
  const bytes = Uint8Array.from(result.result);
  const text = new TextDecoder().decode(bytes).trim().replace(/^"|"$/g, '');
  if (/^[0-9a-fA-F]{64}$/.test(text)) return text.toLowerCase(); // contract returns a JSON hex string
  if (bytes.length === 32) return toHex(bytes);                   // or raw 32 bytes
  throw new Error('unexpected get_root payload (' + bytes.length + ' bytes)');
}

async function readRoot(seq) {
  const body = {
    jsonrpc: '2.0',
    id: 'verify',
    method: 'query',
    params: {
      request_type: 'call_function',
      finality: 'final',
      account_id: CONTRACT,
      method_name: 'get_root',
      args_base64: btoa(JSON.stringify({ seq: Number(seq) }))
    }
  };
  const res = await fetch(NEAR_RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error('RPC HTTP ' + res.status);
  const json = await res.json();
  if (json.error) throw new Error(json.error.message || 'RPC error');
  return { root: rootFromRpcResult(json.result), block: json.result.block_height };
}

/* -------------------------------------------------------------- app state */

let current = null; // { pdr, example, method }

function renderFields(p) {
  const rows = [
    ['size', PDR_TOTAL_LEN + ' bytes (payload ' + PDR_PAYLOAD_LEN + ' + signature 64)'],
    ['version', String(p.version[0])],
    ['signature scheme', SIG_SCHEMES[p.sig_scheme[0]] || String(p.sig_scheme[0]) + ' · unknown'],
    ['payment anchor', PAYMENT_TYPES[p.payment_anchor_type[0]] || String(p.payment_anchor_type[0]) + ' · unknown'],
    ['time (UTC)', p.tsIso + '   (' + p.ts + ')'],
    ['issuer', p.issuerText || '—'],
    ['file SHA-256', toHex(p.payload_hash)],
    ['subject hash', toHex(p.subject_hash)],
    ['merkle root in receipt', isZero(p.merkle_root) ? '00…00 (not committed in this receipt)' : toHex(p.merkle_root)],
    ['tx hash in receipt', isZero(p.tx_hash) ? '00…00 (unset)' : toHex(p.tx_hash)]
  ];
  const dl = $('fields');
  dl.innerHTML = '';
  for (const [k, v] of rows) {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.textContent = v;
    dl.append(dt, dd);
  }
  $('fieldsCard').hidden = false;
}

async function verifyLocal(rawText, example) {
  $('nearOut').hidden = true;
  $('nearNote').textContent = '';

  let decoded;
  try {
    decoded = decodeReceipt(rawText);
  } catch (e) {
    setPlate('plateStruct', 'bad', 'INVALID', e.message);
    setPlate('plateSig', 'idle', 'not checked', 'no receipt to check');
    setPlate('plateAnchor', 'idle', 'not checked', 'no receipt to check');
    $('fieldsCard').hidden = true;
    $('nearCard').hidden = true;
    $('lenInfo').textContent = '';
    current = null;
    return;
  }

  const pdr = decoded.bytes;
  $('lenInfo').textContent = pdr.length + ' bytes · ' + decoded.how;

  if (pdr.length !== PDR_TOTAL_LEN) {
    setPlate('plateStruct', 'bad', 'INVALID', pdr.length + ' bytes, expected ' + PDR_TOTAL_LEN);
    setPlate('plateSig', 'idle', 'not checked', 'malformed receipt');
    setPlate('plateAnchor', 'idle', 'not checked', 'malformed receipt');
    $('fieldsCard').hidden = true;
    $('nearCard').hidden = true;
    current = null;
    return;
  }

  const p = parsePdr(pdr);
  current = { pdr, p, example: example || null };
  renderFields(p);

  // (a) structure
  const issues = [];
  if (p.version[0] !== 3) issues.push('unexpected version ' + p.version[0]);
  if (!p.issuerText) issues.push('empty issuer');
  if (p.ts < 1600000000 || p.ts > 4102444800) issues.push('timestamp out of range');
  if (issues.length) {
    setPlate('plateStruct', 'warn', 'PARSE WARNING', issues.join('; '));
  } else {
    setPlate('plateStruct', 'ok', 'VALID', '239 bytes · v3 · ' + p.issuerText);
  }

  // (b) signature
  setPlate('plateSig', 'idle', 'checking…', 'Ed25519');
  const sigRes = await ed25519Verify(p.signature, p.envelope, fromHex(NOTARY_PUBKEY_HEX));
  if (sigRes.ok === true) {
    setPlate('plateSig', 'ok', 'VERIFIED', sigRes.method);
  } else if (sigRes.ok === false) {
    setPlate('plateSig', 'bad', 'INVALID', sigRes.method + ' — signature does not match this receipt');
  } else {
    setPlate('plateSig', 'warn', 'NOT CHECKED', 'no Ed25519 implementation available in this browser');
  }

  // (c) anchor — needs the chain, so just show what the receipt carries now
  if (!isZero(p.merkle_root)) {
    setPlate('plateAnchor', 'idle', 'root ready', toHex(p.merkle_root).slice(0, 16) + '… · press Check against NEAR');
  } else if (current.example && current.example.path) {
    setPlate('plateAnchor', 'idle', 'proof bundled', 'receipt root is zero · inclusion proof for anchor ' +
      current.example.anchor_seq + ' loaded');
  } else {
    setPlate('plateAnchor', 'warn', 'NO ROOT', 'this receipt carries no anchor root (free / unanchored record)');
  }

  $('nearCard').hidden = false;
  if (example && example.anchor_seq) {
    const hint = example.anchor_seq === 94 ? '' : ' — set from the example';
    $('seq').value = String(example.anchor_seq);
    $('nearNote').textContent = 'anchor seq ' + example.anchor_seq + hint;
  }
}

async function checkNear() {
  if (!current) return;
  const seq = Number($('seq').value);
  const out = $('nearOut');
  const verdict = $('nearVerdict');
  const meta = $('nearMeta');
  out.hidden = false;
  $('localRootLine').hidden = true;
  verdict.className = 'verdict';
  verdict.textContent = 'reading ' + CONTRACT + '…';
  $('onchainRoot').textContent = '…';
  $('receiptRoot').textContent = isZero(current.p.merkle_root)
    ? '00…00 (not committed in this receipt)'
    : toHex(current.p.merkle_root);
  meta.textContent = '';

  let chain;
  try {
    chain = await readRoot(seq);
  } catch (e) {
    verdict.className = 'verdict bad';
    verdict.textContent = 'RPC FAILED — nothing verified';
    meta.textContent = e.message + ' (no claim is made about this receipt)';
    setPlate('plateAnchor', 'bad', 'UNVERIFIED', 'NEAR RPC unreachable');
    return;
  }
  $('onchainRoot').textContent = chain.root;
  let metaBits = ['seq ' + seq, 'block ' + chain.block, 'via rpc.mainnet.near.org'];

  // 1) Merkle inclusion, if the public log published a path for this record
  let foldedHex = null;
  if (current.example && current.example.path) {
    const pathBytes = current.example.path.map(fromHex);
    try {
      const folded = await foldPath(fromHex(current.example.leaf), current.example.index,
        current.example.size, pathBytes);
      foldedHex = toHex(folded);
      $('localRootLine').hidden = false;
      $('localRoot').textContent = foldedHex;
      metaBits.push('leaf ' + current.example.index + ' of ' + current.example.size +
        ' · ' + current.example.path.length + '-node path folded in this tab');
    } catch (e) {
      $('localRootLine').hidden = false;
      $('localRoot').textContent = 'fold error: ' + e.message;
    }
  }

  const receiptRootZero = isZero(current.p.merkle_root);
  const receiptRootHex = toHex(current.p.merkle_root);

  if (foldedHex && foldedHex === chain.root) {
    verdict.className = 'verdict ok';
    verdict.textContent = 'MATCH — this record is in the tree the chain holds';
    setPlate('plateAnchor', 'ok', 'ANCHORED', chain.root.slice(0, 16) + '… @ anchor ' + seq);
  } else if (foldedHex) {
    verdict.className = 'verdict bad';
    verdict.textContent = 'MISMATCH — folded root ≠ on-chain root';
    setPlate('plateAnchor', 'bad', 'MISMATCH', 'folded root differs from get_root(' + seq + ')');
  } else if (!receiptRootZero && receiptRootHex === chain.root) {
    verdict.className = 'verdict ok';
    verdict.textContent = 'MATCH — receipt root equals the on-chain root';
    setPlate('plateAnchor', 'ok', 'ANCHORED', receiptRootHex.slice(0, 16) + '… @ ' + seq);
  } else if (!receiptRootZero) {
    verdict.className = 'verdict bad';
    verdict.textContent = 'MISMATCH — receipt root ≠ on-chain root';
    setPlate('plateAnchor', 'bad', 'MISMATCH', 'receipt root ≠ get_root(' + seq + ')');
  } else {
    verdict.className = 'verdict warn';
    verdict.textContent = 'NO COMMITTED ROOT — nothing to compare';
    setPlate('plateAnchor', 'warn', 'NOT ANCHORED',
      'receipt root is zero; no inclusion proof bundled');
    metaBits.push('free receipts carry a zero root by design — the anchor log holds the proof');
  }

  meta.textContent = metaBits.join(' · ');
}

/* ------------------------------------------------------------------- wiring */

function loadExample(i) {
  const ex = EXAMPLES[i];
  if (!ex) return;
  $('pdr').value = ex.pdr_b64;
  $('exHint').textContent = ex.note;
  verifyLocal(ex.pdr_b64, ex);
}

function clearAll() {
  $('pdr').value = '';
  $('lenInfo').textContent = '';
  $('nearOut').hidden = true;
  $('fieldsCard').hidden = true;
  $('nearCard').hidden = true;
  $('exHint').textContent = 'Real receipts from the public log. Nothing leaves this page ' +
    'until you press “Check against NEAR”.';
  $('seq').value = '94';
  $('nearNote').textContent = '';
  setPlate('plateStruct', 'idle', 'not checked', 'waiting for a receipt');
  setPlate('plateSig', 'idle', 'not checked', 'Ed25519 over the envelope');
  setPlate('plateAnchor', 'idle', 'not checked', 'on-chain root');
  current = null;
}

document.addEventListener('DOMContentLoaded', () => {
  $('verifyBtn').addEventListener('click', () => verifyLocal($('pdr').value, null));
  $('clearBtn').addEventListener('click', clearAll);
  $('nearBtn').addEventListener('click', async () => {
    const btn = $('nearBtn');
    btn.disabled = true;
    const was = btn.textContent;
    btn.textContent = 'Checking…';
    try {
      await checkNear();
    } finally {
      btn.disabled = false;
      btn.textContent = was;
    }
  });
  document.querySelectorAll('.chip[data-ex]').forEach((el) => {
    el.addEventListener('click', () => loadExample(Number(el.dataset.ex)));
  });
});

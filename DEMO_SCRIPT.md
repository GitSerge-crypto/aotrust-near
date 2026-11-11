# AOTrust — 90-second demo, shot by shot

**For:** whoever records the screen (screen recording, no camera, no faces).
**Total length:** 90.0 s. **4 scenes.** Hard stop at 1:30.
**Resolution:** 1920x1080, browser at 110–125% zoom, bookmarks bar hidden, one window, no desktop clutter.
**Voice:** optionally off-camera English, calm, no hype. Full read-through at the end of this file.
**Captions:** burned in, English, ≤60 characters each. Counted below.

The claim the video makes is narrow: *a file existed at a time, and you can check that against NEAR without asking AOTrust*. Nothing else gets said.

---

## Before you press record (10 minutes, do not skip)

| # | Prep | Why |
|---|------|-----|
| 1 | Create a **fresh file** for the demo, e.g. `delivery-spec-v1.pdf`, and never register it before the take. | A previously registered file returns "This file is already registered" → a *reaffirmation*, not a first record. The demo needs a genuine first record. |
| 2 | Open 3 tabs in this order: `shield.aotrust.link` · `verify.aotrust.link` · the repo's `verify/` page. | Scene 3 needs tab switching with zero typing. |
| 3 | Pre-paste a valid receipt into the verify tab once, to confirm it loads, then clear it. | Keeps scene 3 to one paste. |
| 4 | Check the free tier holds: 5 PDR/day per IP. | The demo uses the free path — no wallet, no $0.10 step, nothing to explain in 90 s. |
| 5 | Read the four numbers below off the live journal/contract once, and use *those*. | If today's numbers differ, change this table — do **not** let the video and the repo disagree. |
| 6 | Do one silent rehearsal with a timer. | 25 s for scene 2 and 35 s for scene 3 are the two places people overrun. |

### Numbers allowed on screen (verbatim, nothing invented)

| What | Value |
|---|---|
| Contract | `notary-node.near` |
| Prize wallet | `notary-node.near` |
| Records in the journal | **231** |
| Anchors in local history | **33** |
| On-chain Merkle root | `079074f46263a223bf2ab7af60754111b68609d79c87c5bf1e83b5e158cd7865` (truncate on screen to `079074f4…7865`) |
| Anchor sequence | **94** |
| Receipt size | **239 bytes**, Ed25519 signature, SHA-256 of the file inside |
| Exit kit result | **33/33** local roots match the chain |

Anything not in this table is not said and not shown.

---

## Timeline at a glance

| TC | Dur | Scene | Surface | One-line job |
|---|---|---|---|---|
| 0:00–0:15 | 15 s | 1 · Problem | title card + a file sitting in a folder | make the viewer feel the argument |
| 0:15–0:40 | 25 s | 2 · Receipt | `shield.aotrust.link` | show a receipt appear from one drop |
| 0:40–1:15 | 35 s | 3 · Verify | `verify.aotrust.link` → repo `verify/` | prove it checks out without us |
| 1:15–1:30 | 15 s | 4 · Close | repo README + root on chain | leave one sentence behind |

---

## Scene 1 — 0:00–0:15 · The problem

**Open:** a plain file-manager window with one document in it (`delivery-spec-v1.pdf`). No browser yet.

**Do:**
- 0:00 hold on the file, cursor not moving.
- 0:04 slowly open the file's "Get info" / properties panel — size and a date. Nothing else.
- 0:09 cut to a title card, black, one white line.

**On screen must show:** a real file, a real date field, then the title card. No stock footage, no animation, no logo sting.

**Caption (on the title card, burns in at 0:09):**
`The file exists. The date is the argument.` — **42 chars**

**Voiceover:**
> "An agent hands over a file. A week later the client says it was edited after delivery. The file is the same. The argument is about time. Right now, whoever holds the server wins that argument."

**Editor note:** the properties panel must not show an owner name or a path that identifies the client. Blur or pick a clean file.

---

## Scene 2 — 0:15–0:40 · One drop, one receipt

**Open:** `shield.aotrust.link`, already loaded, drop zone centered.

**Do:**
- 0:15 page is idle. Cursor enters frame, not yet on the drop zone.
- 0:18 drag `delivery-spec-v1.pdf` from the file-manager window into the drop zone. Drop it.
- 0:20–0:26 let the progress state run — do not cut it out, the wait is the point.
- 0:26 result state appears. Cursor moves down the four fields, one at a time, unhurried: hash → time → `first record` → record number.
- 0:33 cursor rests. Hold. No scrolling, no clicking "download PDF".

**On screen must show (all four, readable at 1080p):**
1. the drop zone text before the drop — "Drop your file here or click to browse"
2. the line "Your file never leaves your browser. Only a SHA-256 hash is sent."
3. the result header — **File Shielded**
4. a receipt block containing: **SHA-256** (full 64 chars, or first 8 + last 4 with the rest legible if you zoom), **timestamp**, the words **first record**, and **record #** with its number

If the result instead says "This file is already registered" — stop, make a new file, start the take again. Do not narrate around it.

**Caption (burns in at 0:28, bottom-left, small):**
`One drop. 239-byte receipt, first record.` — **41 chars**

**Voiceover:**
> "So we hash the file instead of storing it. Drop it on shield dot aotrust dot link. The SHA-256 is computed in the browser. The file never leaves the machine. What comes back is a 239-byte receipt: the hash, the time, the record number, and a signature. This one is marked first record."

**Editor note:** if the receipt number is small on screen, add a 1.5 s zoom to the receipt block at 0:30 — a hard cut-zoom, not a slow Ken Burns.

---

## Scene 3 — 0:40–1:15 · Verify, then verify without us

**Open:** `verify.aotrust.link` in the active tab; repo `verify/` page in the next tab.

**Do:**
- 0:40 paste the receipt text (or the receipt link) into the paste box. Submit.
- 0:43 green result appears. Hold on the words **Receipt verified** for a full 2 s.
- 0:46 scroll ~one screen to the proof block: **Signature authentic**, the Ed25519 line, the SHA-256. Stop.
- 0:52 switch tab to the repo's `verify/` page (local file or Pages URL — whatever the README links).
- 0:55 drop the same receipt into it. The page recomputes the hash and folds the Merkle proof in the browser.
- 0:58 click **Check against NEAR**.
- 1:01 the comparison renders. Cursor sits on the matched root line.
- 1:03 hold, then a 2 s zoom on the root: `079074f4…7865` and **anchor 94**.
- 1:09 back to full frame. Hold still until 1:15.

**On screen must show:**
1. `verify.aotrust.link` result: **Receipt verified** / **Cryptographically verified**
2. the signature line — "Signature authentic", Ed25519, and the explicit note that the record was signed by AOTrust (`notary-node.near`) and anchored to NEAR
3. the repo `verify/` page **with its URL bar visible** — the viewer must see this is a different origin from aotrust.link
4. the button, plainly labelled **Check against NEAR**
5. the result of that check: local recomputed root **equals** the on-chain root, with the root string and anchor sequence on screen

If the on-chain read fails during the take, do **not** fake the green state and do not cut to a mock. Stop, re-record. A demo that shows a real failure honestly beats one that shows an invented pass — and this video's only asset is that it is real.

**Caption 1 (burns in at 0:44):**
`Proof checked against NEAR, not against us.` — **43 chars**

**Caption 2 (optional, burns in at 1:04, same style):**
`Root 079074f4…7865 · anchor 94` — **30 chars**

**Voiceover:**
> "Paste the receipt into verify dot aotrust dot link. Signature checks out. But you should not have to trust that page either. So there is a second page, in the repository, that does the same check with no AOTrust server in the path: recompute the hash, fold the Merkle proof, read the root from the notary-node contract. Check against NEAR. Root zero seven nine zero, anchor ninety-four. Match."

**Editor note:** the URL bar is the argument in this scene. Never crop it out, never zoom past it.

---

## Scene 4 — 1:15–1:30 · Close

**Open:** the repo `README.md` rendered on GitHub (`github.com/GitSerge-crypto/aotrust-near`), scrolled to the section that lists the contract and the exit kit.

**Do:**
- 1:15 cut to the README. Cursor moves once, down to `notary-node.near`, and stops.
- 1:20 cut to a terminal or the exit-kit output, showing the `33/33` line against the live journal. Hold 6 s.
- 1:26 cut to the end card: black, two lines, no logo animation.

**On screen must show:** the contract account name, the exit-kit summary line (`33/33` roots matched), then the end card.

**End card text:**
```
AOTrust — NEAR Hackathon 2026
github.com/GitSerge-crypto/aotrust-near
```

**Caption (end card second line, replaces the repo line if you prefer it typed):**
`Verifiable without the vendor.` — **30 chars**

**Voiceover:**
> "That is the whole claim. Existence at a time, proven by a signature and a root already on NEAR. You do not need us to believe it. The exit kit replays all thirty-three anchors against the chain."

---

## Full voiceover read-through (194 words, ~129 wpm — fits 90 s with room)

> An agent hands over a file. A week later the client says it was edited after delivery. The file is the same. The argument is about time. Right now, whoever holds the server wins that argument.
>
> So we hash the file instead of storing it. Drop it on shield dot aotrust dot link. The SHA-256 is computed in the browser. The file never leaves the machine. What comes back is a 239-byte receipt: the hash, the time, the record number, and a signature. This one is marked first record.
>
> Paste the receipt into verify dot aotrust dot link. Signature checks out. But you should not have to trust that page either. So there is a second page, in the repository, that does the same check with no AOTrust server in the path: recompute the hash, fold the Merkle proof, read the root from the notary-node contract. Check against NEAR. Root zero seven nine zero, anchor ninety-four. Match.
>
> That is the whole claim. Existence at a time, proven by a signature and a root already on NEAR. You do not need us to believe it. The exit kit replays all thirty-three anchors against the chain.

Silent version: keep all captions, drop the voiceover, add `231 records · 33 anchors · root on chain` as a small persistent lower-third in scenes 2–3.

---

## Caption sheet (for the editor)

| # | TC in | TC out | Text | Chars |
|---|---|---|---|---|
| C1 | 0:09 | 0:15 | `The file exists. The date is the argument.` | 42 |
| C2 | 0:28 | 0:40 | `One drop. 239-byte receipt, first record.` | 41 |
| C3 | 0:44 | 0:52 | `Proof checked against NEAR, not against us.` | 43 |
| C4 | 1:04 | 1:09 | `Root 079074f4…7865 · anchor 94` | 30 |
| C5 | 1:26 | 1:30 | `Verifiable without the vendor.` | 30 |

Style: one line, bottom-left, 32 px, white on 60% black bar, no shadow, no fade longer than 200 ms.

---

## Do not put on screen

- Any number that is not in the "Numbers allowed on screen" table.
- The words *trustless*, *revolutionary*, *guaranteed*, *legal proof*, *ownership*.
- A fabricated green check. If a check fails on camera, re-record.
- The $0.10 wallet flow. It costs 20 s of the 90 and raises a question the video has no time to answer.
- A face, a webcam, a music bed louder than the voice.

---

## Deliverables from the recording session

- `demo-90s.mp4` — H.264, 1920x1080, 30 fps, audio AAC 128 kbps.
- `demo-90s-silent.mp4` — same cut, captions only.
- `demo-90s.srt` — captions + voiceover as subtitles, because the jury and the scrapers both read text.

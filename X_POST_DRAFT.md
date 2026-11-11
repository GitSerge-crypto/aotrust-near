# X post drafts — AOTrust / NEAR Hackathon

Three ready-to-paste options. Nothing here is published; pick one, paste, check the counter, post.

**Account assumption:** free tier, 280 characters, one link max. Counts below are exact for the text as written (URL in short form `github.com/...`, which X wraps to 23 characters — raw and weighted counts are both given, and all three pass on both).

**Every variant carries:** `@NEARProtocol`, `#NEARHackathon`, the words "Built at NEAR HACKATHON", one repo link, and an explicit ask for feedback.

---

## (a) Problem first — recommended

```
You send a client a file. Later they say it changed after delivery.

AOTrust hashes it and anchors that hash hourly on NEAR. The date becomes provable.

Built at NEAR HACKATHON
@NEARProtocol #NEARHackathon
github.com/GitSerge-crypto/aotrust-near
Feedback welcome.
```

**Length:** 263 characters raw · 247 as X counts it (link = 23) · 17 characters of headroom.

---

## (b) Technical — proof without a vendor

```
239-byte receipt: your file's SHA-256 + Ed25519 signature.
The Merkle root lands on notary-node.near every hour.
Verification needs no AOTrust server.

Built at NEAR HACKATHON
@NEARProtocol #NEARHackathon
github.com/GitSerge-crypto/aotrust-near
Tell me what breaks.
```

**Length:** 265 characters raw · 249 as X counts it · 15 characters of headroom.

---

## (c) Short and blunt

```
Proof a file existed shouldn't need our permission.

231 records. Hourly root on NEAR. Check it yourself.

Built at NEAR HACKATHON
@NEARProtocol #NEARHackathon
github.com/GitSerge-crypto/aotrust-near
Roast it.
```

**Length:** 209 characters raw · 193 as X counts it · 71 characters of headroom.

---

## Verification table

| Requirement | (a) | (b) | (c) |
|---|---|---|---|
| `@NEARProtocol` present | ✅ | ✅ | ✅ |
| `#NEARHackathon` present | ✅ | ✅ | ✅ |
| Says it was built at NEAR HACKATHON | ✅ "Built at NEAR HACKATHON" | ✅ same | ✅ same |
| First line readable by a stranger | ✅ a situation, no jargon | ⚠️ needs to know what a receipt/hash is | ✅ a claim anyone can parse |
| Exactly one link, to the repo | ✅ | ✅ | ✅ |
| Asks for feedback | ✅ "Feedback welcome." | ✅ "Tell me what breaks." | ✅ "Roast it." |
| Under 280 raw | ✅ 263 | ✅ 265 | ✅ 209 |
| Under 280 weighted | ✅ 247 | ✅ 249 | ✅ 193 |
| No claim the project cannot back | ✅ | ✅ | ✅ |

---

## Recommendation: (a), with (b) as the first reply

**Why (a):** the hackathon post is read by people who have never heard of AOTrust, and by judges skimming a timeline. (a) is the only variant whose first line lands without jargon — it describes a situation the reader has been in, and the second line says what the project does about it. The technical payload is thin on purpose: the repo and the video carry that weight.

**Why not (b) as the post:** its first line is a spec, not a hook. "239-byte receipt" is precise and it is the detail that makes a technical judge believe the thing is real — but it filters out everyone else at character one. It works far better as the immediate reply, where the reader has already opted in.

**Why not (c):** "Roast it" invites hostile replies on a post that is meant to be a submission artifact. It is the right tone for a later post once there is feedback to respond to, not for the one the jury sees first.

**Suggested use of all three:**
1. Post (a) as the submission post.
2. Reply immediately with (b) — same thread, so the detail is one click away and the main post stays short.
3. If the thread gets traction, post (c) standalone a day later, pointing at the repo.

---

## Posting notes

- Put the video in the reply (or quote-post it), not the main post — one link only, and a bare repo link is the one a judge will actually click.
- Attach the video natively to the reply if it is under the size cap; a YouTube link inside a reply is fine.
- Alt text for the attached image/video still, if you add one: *"Terminal-style view of an AOTrust receipt: SHA-256 hash, timestamp, first record, Ed25519 signature, next to the matching Merkle root 079074f4…7865 anchored on NEAR."*
- Do not add a second hashtag beyond `#NEARHackathon`; it eats characters and buys nothing.
- Check the counter in the composer before posting — the counts above assume no auto-inserted link preview text, and the short-form URL is wrapped by X, not expanded.
- If you ever swap the short form for `https://github.com/GitSerge-crypto/aotrust-near`, add 8 raw characters; every variant still fits.

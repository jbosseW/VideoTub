# VideoTub — Gap Analysis & Roadmap

_Written 2026-07-03._

## ✅ Shipped (this pass)

Tiers 1 & 2 are largely done: **thumbnails**, **transcode-to-playable** (ffmpeg),
**admin moderation dashboard** (`/admin.html`), **SQLite** storage, **Docker
Compose** + Dockerfile, **perceptual-hash** re-upload blocking, **ClamAV**
cross-platform malware scanning, and a **jest/supertest suite + GitHub Actions
CI**. Plus most of Tier 3: **search, tag filtering, pagination, view counts,
configurable retention, and an embed player**. The main item left is an
S3-style storage backend (below).

---

## Where it is now

A working anonymous short-clip host: upload → 24h auto-delete → watch, with a
genuinely solid **trust & safety** layer already in place — proof-of-work upload
gate, magic-byte + ffprobe validation, hash/word denylists, an optional NudeNet
content-scan hook, a pre-publish approval queue, report→auto-takedown, IP +
browser-fingerprint bans, rate limiting, and security headers. The product/UX
and scale layers are where it's thin.

---

## Tier 1 — makes it feel like a real video site (highest impact)

### 1. Thumbnails
No previews today; the listing is text cards. Generate a poster frame with
`ffmpeg` at upload (`-ss 1 -frames:v 1`), store it next to the video, show it in
the grid and — importantly — in the **admin review queue** so moderation is
visual. Single biggest perceived-quality jump.

### 2. Make every upload actually play
Playback is a native `<video src>`. `.mp4` (H.264) and `.webm` play; **`.mkv`,
`.avi`, and some `.mov` do not** in most browsers — so a chunk of allowed uploads
are un-watchable. Options: (a) transcode to web-safe H.264 mp4 / VP9 webm with
ffmpeg on upload (async, mark "processing"), or (b) restrict allowed types to
web-playable ones. Transcoding is the "real site" answer.

### 3. Admin moderation dashboard (UI)
Admin is API-only (curl + `x-admin-key`). A small web dashboard — review queue
with thumbnails, approve / remove / ban / block-hash buttons, a reports view, and
the moderation log — makes the approval queue and reporting *usable* instead of
theoretical. This is what turns the safety features from "present" into "used."

### 4. SQLite instead of the JSON file
`data/videos.json` is rewritten on every change and has concurrent-write races
under load. `better-sqlite3` is a near drop-in (synchronous, atomic, indexed) and
removes the single biggest scale/reliability wall. Do this before any real traffic.

### 5. One-command deploy (Docker Compose)
Ship a `Dockerfile` + `compose.yml` bundling Node + ffmpeg (+ optional ClamAV).
Anonymous-upload apps live or die on being easy to stand up *correctly*; a
compose file that wires the env vars and volumes is the difference between a repo
and a product.

---

## Tier 2 — trust & safety depth

### 6. Perceptual hashing (near-duplicate blocking)
The hash denylist is exact-match only — re-encode one frame and it slips through.
A perceptual video hash (pHash of sampled frames) lets you block *near*-duplicates
of removed content. The strongest upgrade to the "stays down when taken down"
guarantee.

### 7. Cross-platform malware scanning (ClamAV)
Malware scan is Windows-Defender-only; on Linux it either blocks everything or
runs unscanned. Add a ClamAV path (`clamdscan`) so a Linux host gets real
scanning without the `ALLOW_UNSCANNED_UPLOADS` escape hatch.

### 8. Tests + CI
No test suite for a lot of security-critical logic (PoW verify, report threshold,
token/admin auth, denylists, ban gates). Add jest + supertest covering those
paths and a GitHub Actions workflow. Given the trust & safety surface, this is
higher-value here than on a typical toy app.

---

## Tier 3 — product polish

- **Pagination / lazy-load** — the listing fetches *all* videos; it won't scale
  past a few dozen. Page or infinite-scroll the `/api/videos` feed.
- **Search + tags/categories** — "game clips" vs "memes"; find things.
- **View counts** (and optionally likes) — basic engagement signal.
- **Configurable retention** — let the uploader pick 1h / 24h / 7d TTL.
- **Responsive/mobile layout + shareable embed player** (oEmbed) for posting
  clips elsewhere.
- **Storage abstraction (S3-compatible)** — optional backend so it isn't pinned
  to one box's disk.

## Suggested sequencing

1. **Thumbnails + admin dashboard + SQLite** — the trio that makes it feel and
   run like a real, moderatable site.
2. **Transcode-to-playable** (or restrict types) so nothing is un-watchable.
3. **Docker Compose** for easy correct deploys.
4. **pHash + ClamAV + tests/CI** — harden the safety layer for real traffic.
5. Tier-3 polish as usage grows.

## Deliberately *not* recommended
- **Comments** — another anonymous moderation surface with poor payoff; skip
  unless there's demand, and only with the same report/takedown machinery.
- **Real-money anything** — keep it free; monetization would pull in a heavier
  compliance burden.
- Dropping anonymity for accounts — it's a defining feature; if durable identity
  is needed, prefer optional PoW-gated pseudonyms over mandatory accounts.

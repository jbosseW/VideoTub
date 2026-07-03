# VideoTub

> **Scope: private / LAN / trusted-group use only.** This is a small
> self-hosted tool, not a public video platform. See
> [Deployment warning & liability](#deployment-warning--liability) before
> exposing it to the internet.

Anonymous YouTube-style mini app:
- Upload videos (no login)
- Browse uploaded videos
- Watch videos in browser
- Malware scan before publish (Windows Defender)
- Auto-delete videos after 24 hours

**Moderation & abuse controls (built in):**
- **Proof-of-work gate** — every upload must solve a SHA-256 PoW puzzle
  (`pow.js`, ~1-2s in a browser Web Worker) before it's accepted. Raises the cost
  of bots/automation/spam. On by default; `POW_DISABLED=true` to turn off.
- **Real video validation** — uploads are checked by magic bytes (a non-video
  renamed `.mp4` is rejected), and, if `ffprobe` is installed, must decode as
  video and be within `MAX_DURATION_SEC` (default 15 min — keeps out long-form).
- **Pluggable content scanner** — set `CONTENT_SCAN_CMD` to an external NSFW/ML
  classifier (see `tools/nsfw_scan.py` for a ready-to-use NudeNet scanner). It's
  given the file path; non-zero exit rejects the upload (fails closed).
- **Pre-publish approval** — `REQUIRE_APPROVAL=true` holds every upload for admin
  review before it's listed/watchable. The strongest guard for a shared instance.
- **Content denylist** — uploads are SHA-256 hashed and rejected if the hash is
  on `data/hash-blocklist.txt`. A text denylist (`data/word-blocklist.txt`, plus
  a small built-in seed list) rejects banned terms in titles/descriptions.
- **Reporting → auto-takedown** — anyone can report a video; after
  `REPORT_AUTO_REMOVE` (default 3) distinct reports it is automatically removed.
- **Deletion** — uploaders get a one-time delete key (stored only as a hash) to
  remove their own video; admins can force-remove any video.
- **Bans** — uploaders are identified by a salted IP hash *and* a browser
  fingerprint hash (an IP change alone doesn't dodge a ban). Admins can ban on
  removal (`?ban=1`). Note: a device MAC address is **not** obtainable by a web
  server, so a fingerprint is the closest durable signal (and is defeatable).
- **Rate limiting** — per-IP caps on uploads and reports (in-memory).
- **Admin API** — review/approve, force-delete, ban, and manage denylists, gated
  by `ADMIN_KEY`.
- **Security headers** — CSP, `nosniff`, frame/referrer/CORP policies on every
  response.
- **Privacy** — uploader IPs are stored only as per-process salted hashes, never
  in plaintext.

## Security + Limits
- Allowed file types only: `.mp4`, `.webm`, `.mkv`, `.mov`, `.avi`, `.m4v`
- Default max upload size: `250 MB`
- Retention: `24 hours` (then auto-deleted)
- Scanner: `MpCmdRun.exe` (Windows Defender)

Uploads are blocked if scanning fails or malware is detected.

> **⚠️ The malware scanner is Windows-only.** It shells out to Windows Defender
> (`MpCmdRun.exe`). On Linux/macOS the scanner isn't found, so with the default
> `ALLOW_UNSCANNED_UPLOADS=false` **every upload is blocked** (fails safe). To run
> on a non-Windows host you must set `ALLOW_UNSCANNED_UPLOADS=true`, which means
> **uploads are stored with no malware scanning at all.** Only do that behind a
> trusted network, or wire in a cross-platform scanner (e.g. ClamAV) first.

## Security notes (from a review pass)

The code is syntactically clean, boots, and handles the basics well: file-type
allowlist (extension + MIME), size cap, UUID stored filenames (no path traversal),
24h TTL cleanup, and **user text is HTML-escaped** on the listing page and rendered
via `textContent` on the watch page (no stored XSS). Known gaps, by design or not:

- **No rate limiting** — anonymous unlimited uploads can exhaust disk. Add one
  before any exposed deployment.
- **No content verification beyond extension/MIME** — both are client-supplied; a
  non-video file renamed `.mp4` would be stored (it just won't play). No magic-byte
  or `ffprobe` check.
- **No security headers** (`X-Content-Type-Options: nosniff`, CSP). Low risk given
  the extension allowlist, but worth adding.
- **JSON-file datastore** — concurrent uploads can race on the write. Fine for
  light/trusted use, not for scale.
- **No delete/report/takedown endpoint** — see the deployment warning below.

## Run
1. Open terminal in this folder
2. Install deps:
   - `npm.cmd install`
3. Start server:
   - `npm.cmd start`
4. Open:
   - `http://localhost:3000`

## Optional Env Vars
- `PORT` (default `3000`)
- `MAX_UPLOAD_MB` (default `250`)
- `ALLOW_UNSCANNED_UPLOADS` (default `false`; set `true` only for local dev fallback)
- `ADMIN_KEY` — enables the admin moderation API when set (sent as `x-admin-key`)
- `REPORT_AUTO_REMOVE` (default `3`) — distinct reports before auto-takedown
- `UPLOAD_RATE_MAX` (default `5`) / `REPORT_RATE_MAX` (default `20`) per window
- `RATE_WINDOW_MS` (default `600000` = 10 min)
- `POW_DISABLED` (default off) / `POW_DIFFICULTY` (default `18` leading zero bits)
- `REQUIRE_APPROVAL` (default `false`) — hold uploads for admin approval
- `MAX_DURATION_SEC` (default `900`) — max clip length (needs `ffprobe`)
- `CONTENT_SCAN_CMD` — external content scanner; file path appended as last arg

### NSFW content scanning (optional)

`tools/nsfw_scan.py` is a ready-to-use scanner: it samples frames with `ffmpeg`
and runs the open-source **NudeNet** detector, rejecting the upload if disallowed
content is found. Enable it:

```
pip install nudenet          # on the host running VideoTub
# ffmpeg must be on PATH
CONTENT_SCAN_CMD="python tools/nsfw_scan.py" node server.js
```

It fails closed (rejects) if `nudenet`/`ffmpeg` are missing, so scanning is never
silently skipped once enabled. Swap in any other classifier or a cloud
moderation API the same way — VideoTub just runs the command and checks the exit
code (0 = allow, non-zero = reject).

## Moderation API & files

- **`data/hash-blocklist.txt`** — one SHA-256 hex hash per line; matching uploads
  are rejected. **`data/word-blocklist.txt`** — one banned term per line (matched
  in title/description/filename). Both reload live; `#` lines are comments.
- **`data/moderation.log`** — appended record of reports, removals, and blocks.
- **`data/ip-banlist.txt`** — banned uploader hashes (IP-hash or fingerprint-hash).
- **Endpoints:**
  - `GET /api/pow/challenge` — get a proof-of-work challenge (client solves it).
  - `POST /api/videos/:id/report` `{reason}` — report; auto-removes at threshold.
  - `DELETE /api/videos/:id` `{token}` — uploader deletes via their delete key.
  - `GET /api/admin/videos` — all videos + reports + approval state *(x-admin-key)*.
  - `POST /api/admin/videos/:id/approve` — approve a held upload.
  - `DELETE /api/admin/videos/:id?block=1&ban=1` — force-remove; optionally
    denylist the file's hash and ban the uploader (IP + fingerprint).
  - `POST /api/admin/blocklist` `{hash}` — add a file hash to the denylist.
  - `POST /api/admin/ban` `{ipHash}` — ban an uploader hash.

> These controls make abuse handling *possible*; they are not a substitute for a
> human moderator, legal review, or the operator duties in the warning below.

## Deployment warning & liability

This project now ships **basic** abuse controls (reporting + auto-takedown, a
hash/word denylist, admin removal, rate limiting, security headers). Those make
responsible operation *possible*, but they are a floor, not a compliant service.
It still does **not** include:

- a human moderation/review queue or proactive content scanning (the hash
  denylist only blocks files you already know are bad; it cannot detect *new*
  illegal content)
- a DMCA designated agent or formal notice-and-counter-notice workflow
- a terms of service, age verification, or user accounts
- request logging/retention suitable for responding to legal process
- known-hash matching against authoritative sources (e.g. NCMEC/PhotoDNA) —
  the denylist is a manual hook you must populate

The built-in malware scan checks files for malware — it does not and cannot
judge *content*. If you operate an instance that accepts uploads from
strangers, **you** are the service operator: obligations around illegal
content (including mandatory reporting duties in many jurisdictions),
copyright takedowns, and abuse handling fall on you, not on this codebase
or its authors. Do not deploy this on the open internet without adding the
remaining operational and legal machinery.

**The 24-hour auto-delete is not a legal shield.** Ephemerality does not remove
an operator's duties: if illegal material (e.g. CSAM) is uploaded, reporting and
preservation obligations can attach *regardless* of automatic deletion. The
built-in reporting/takedown lets users flag and remove content, but it does not
detect illegal uploads for you. Treat "it deletes itself" as a privacy feature,
not a compliance strategy.

**Recommendation:** run this only on a private/LAN/trusted network. Do not expose
an anonymous public instance without first adding content moderation, a
report/takedown workflow, rate limiting, request logging suitable for legal
process, a terms of service, and independent legal review for your jurisdiction.

This software is provided **"as is", without warranty of any kind**; the
authors accept no liability for how deployed instances are used. See
[LICENSE](LICENSE).

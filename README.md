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
- **Content denylist** — uploads are SHA-256 hashed and rejected if the hash is
  on `data/hash-blocklist.txt` (operator-maintained; the hook for blocking
  known-bad/illegal files). A text denylist (`data/word-blocklist.txt`) rejects
  banned terms in titles/descriptions.
- **Reporting → auto-takedown** — anyone can report a video; after
  `REPORT_AUTO_REMOVE` (default 3) distinct reports it is automatically removed.
- **Deletion** — uploaders get a one-time delete key (stored only as a hash) to
  remove their own video; admins can force-remove any video.
- **Rate limiting** — per-IP caps on uploads and reports (in-memory).
- **Admin API** — list videos + reports, force-delete, and add hashes to the
  denylist, gated by an `ADMIN_KEY`.
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

## Moderation API & files

- **`data/hash-blocklist.txt`** — one SHA-256 hex hash per line; matching uploads
  are rejected. **`data/word-blocklist.txt`** — one banned term per line (matched
  in title/description/filename). Both reload live; `#` lines are comments.
- **`data/moderation.log`** — appended record of reports, removals, and blocks.
- **Endpoints:**
  - `POST /api/videos/:id/report` `{reason}` — report; auto-removes at threshold.
  - `DELETE /api/videos/:id` `{token}` — uploader deletes via their delete key.
  - `GET /api/admin/videos` — all videos + reports *(header `x-admin-key`)*.
  - `DELETE /api/admin/videos/:id?block=1` — force-remove (and optionally
    denylist the file's hash).
  - `POST /api/admin/blocklist` `{hash}` — add a hash to the denylist.

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

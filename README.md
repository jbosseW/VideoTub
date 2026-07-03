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

## Deployment warning & liability

This project is **deliberately minimal** and is designed for private, LAN,
or trusted-group use. It intentionally does **not** include the things a
publicly reachable upload service is responsible for:

- no content moderation, review queue, or abuse-report mechanism
- no takedown workflow (DMCA or otherwise) and no designated agent
- no terms of service, age gating, or user accounts
- no request logging suitable for responding to legal process
- no rate limiting

The built-in malware scan checks files for malware — it does not and cannot
judge *content*. If you operate an instance that accepts uploads from
strangers, **you** are the service operator: obligations around illegal
content (including mandatory reporting duties in many jurisdictions),
copyright takedowns, and abuse handling fall on you, not on this codebase
or its authors. Do not deploy this on the open internet without adding the
missing operational and legal machinery.

**The 24-hour auto-delete is not a legal shield.** Ephemerality does not remove
an operator's duties: if illegal material (e.g. CSAM) is uploaded, reporting and
preservation obligations can attach *regardless* of automatic deletion, and there
is currently **no in-app way to report, review, or take down a specific video**
before it expires. Treat "it deletes itself" as a privacy feature, not a
compliance strategy.

**Recommendation:** run this only on a private/LAN/trusted network. Do not expose
an anonymous public instance without first adding content moderation, a
report/takedown workflow, rate limiting, request logging suitable for legal
process, a terms of service, and independent legal review for your jurisdiction.

This software is provided **"as is", without warranty of any kind**; the
authors accept no liability for how deployed instances are used. See
[LICENSE](LICENSE).

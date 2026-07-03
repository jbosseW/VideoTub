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

This software is provided **"as is", without warranty of any kind**; the
authors accept no liability for how deployed instances are used. See
[LICENSE](LICENSE).

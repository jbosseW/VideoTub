# VideoTub

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

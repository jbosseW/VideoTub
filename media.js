// media.js — ffmpeg-backed helpers: thumbnails, transcoding, perceptual hash.
// Every function degrades gracefully (returns a benign result) when ffmpeg is
// not installed, so the app still runs — those features simply no-op.

const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

let _hasFfmpeg = null;
function hasFfmpeg() {
  if (_hasFfmpeg === null) {
    try {
      const r = spawnSync("ffmpeg", ["-version"], { windowsHide: true });
      _hasFfmpeg = r.status === 0;
    } catch (_) {
      _hasFfmpeg = false;
    }
  }
  return _hasFfmpeg;
}

function run(cmd, args, timeoutMs = 120000) {
  return new Promise((resolve) => {
    let err = "";
    let child;
    try {
      child = spawn(cmd, args, { windowsHide: true });
    } catch (e) {
      resolve({ code: -1, err: String(e) });
      return;
    }
    const to = setTimeout(() => { try { child.kill(); } catch (_) {} }, timeoutMs);
    child.stderr.on("data", (d) => { err += d.toString(); });
    child.on("error", (e) => { clearTimeout(to); resolve({ code: -1, err: String(e) }); });
    child.on("close", (code) => { clearTimeout(to); resolve({ code, err }); });
  });
}

// Extract a poster frame ~1s in. Returns the thumb path or null.
async function makeThumbnail(videoPath, outPath) {
  if (!hasFfmpeg()) return null;
  const r = await run("ffmpeg", [
    "-v", "error", "-ss", "1", "-i", videoPath,
    "-frames:v", "1", "-vf", "scale=320:-1", "-y", outPath,
  ]);
  return r.code === 0 && fs.existsSync(outPath) ? outPath : null;
}

// Transcode to web-playable H.264/AAC mp4 when the source isn't browser-safe.
// Returns the new path on success, or null (caller keeps the original).
async function transcodeToMp4(videoPath, outPath) {
  if (!hasFfmpeg()) return null;
  const r = await run("ffmpeg", [
    "-v", "error", "-i", videoPath,
    "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
    "-c:a", "aac", "-movflags", "+faststart", "-y", outPath,
  ], 600000);
  return r.code === 0 && fs.existsSync(outPath) ? outPath : null;
}

// Extensions browsers reliably play inline. Others get transcoded if possible.
const WEB_PLAYABLE = new Set([".mp4", ".m4v", ".webm"]);
function isWebPlayable(ext) {
  return WEB_PLAYABLE.has((ext || "").toLowerCase());
}

// Perceptual hash (aHash): downscale a mid-frame to 8x8 grayscale, threshold on
// the mean, pack into a 16-hex-char string. Enables near-duplicate detection.
// Returns "" if ffmpeg is missing or extraction fails.
async function perceptualHash(videoPath) {
  if (!hasFfmpeg()) return "";
  const tmp = videoPath + ".phash.gray";
  const r = await run("ffmpeg", [
    "-v", "error", "-ss", "1", "-i", videoPath, "-frames:v", "1",
    "-vf", "scale=8:8,format=gray", "-f", "rawvideo", "-y", tmp,
  ]);
  try {
    if (r.code !== 0 || !fs.existsSync(tmp)) return "";
    const buf = fs.readFileSync(tmp);
    if (buf.length < 64) return "";
    let sum = 0;
    for (let i = 0; i < 64; i++) sum += buf[i];
    const mean = sum / 64;
    let bits = "";
    for (let i = 0; i < 64; i++) bits += buf[i] >= mean ? "1" : "0";
    // pack 64 bits -> 16 hex chars
    let hex = "";
    for (let i = 0; i < 64; i += 4) hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
    return hex;
  } catch (_) {
    return "";
  } finally {
    try { fs.unlinkSync(tmp); } catch (_) {}
  }
}

module.exports = { hasFfmpeg, makeThumbnail, transcodeToMp4, isWebPlayable, perceptualHash };

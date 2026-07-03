const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawn, spawnSync } = require("child_process");

const express = require("express");
const multer = require("multer");

const pow = require("./pow");
const db = require("./db");
const media = require("./media");
const POW_REQUIRED = process.env.POW_DISABLED !== "true"; // on by default

const app = express();

const PORT = Number(process.env.PORT || 3000);
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 250);
const MAX_FILE_SIZE = Math.max(1, Math.floor(MAX_UPLOAD_MB)) * 1024 * 1024;

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
// Runtime dirs can be redirected (tests, custom deploy layouts) via env.
const RUNTIME_DIR = process.env.VIDEOTUB_RUNTIME_DIR || ROOT;
const DATA_DIR = path.join(RUNTIME_DIR, "data");
const TMP_DIR = path.join(RUNTIME_DIR, "tmp");
const VIDEO_DIR = path.join(RUNTIME_DIR, "videos");
const THUMB_DIR = path.join(RUNTIME_DIR, "thumbs");
const STRICT_SCANNER = process.env.ALLOW_UNSCANNED_UPLOADS !== "true";

// Configurable retention: uploader picks from an allowlist; default 24h.
const ALLOWED_RETENTION_HOURS = [1, 6, 24, 168];
const DEFAULT_RETENTION_HOURS = 24;
const PAGE_SIZE = Math.max(1, Number(process.env.PAGE_SIZE || 24));

// --- Moderation / rate limiting / protection config -------------------------
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const REPORT_AUTO_REMOVE = Math.max(1, Number(process.env.REPORT_AUTO_REMOVE || 3));
const UPLOAD_RATE_MAX = Math.max(1, Number(process.env.UPLOAD_RATE_MAX || 5));
const REPORT_RATE_MAX = Math.max(1, Number(process.env.REPORT_RATE_MAX || 20));
const RATE_WINDOW_MS = Math.max(1000, Number(process.env.RATE_WINDOW_MS || 10 * 60 * 1000));
const HASH_BLOCKLIST_FILE = path.join(DATA_DIR, "hash-blocklist.txt");
const WORD_BLOCKLIST_FILE = path.join(DATA_DIR, "word-blocklist.txt");
const IP_BANLIST_FILE = path.join(DATA_DIR, "ip-banlist.txt");
const PHASH_BLOCKLIST_FILE = path.join(DATA_DIR, "phash-blocklist.txt");
const MOD_LOG_FILE = path.join(DATA_DIR, "moderation.log");

const IP_SALT = crypto.randomBytes(16).toString("hex");

const MAX_DURATION_SEC = Math.max(1, Number(process.env.MAX_DURATION_SEC || 900));
const REQUIRE_APPROVAL = process.env.REQUIRE_APPROVAL === "true";
const CONTENT_SCAN_CMD = process.env.CONTENT_SCAN_CMD || "";
const DEFAULT_BLOCKED_TERMS = ["childporn", "child porn", "cp video", "underage", "r@pe"];

const ALLOWED_EXTENSIONS = new Set([".mp4", ".webm", ".mkv", ".mov", ".avi", ".m4v"]);
const ALLOWED_MIME_TYPES = new Set([
  "video/mp4", "video/webm", "video/x-matroska",
  "video/quicktime", "video/x-msvideo", "video/x-m4v",
]);

for (const dir of [DATA_DIR, TMP_DIR, VIDEO_DIR, THUMB_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}
db.init(DATA_DIR);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function safeString(value, maxLen = 200) {
  if (typeof value !== "string") return "";
  return value.trim().replace(/\s+/g, " ").slice(0, maxLen);
}
function extensionFor(fileName) {
  return path.extname(fileName || "").toLowerCase();
}
function isAllowedUpload(file) {
  const ext = extensionFor(file.originalname);
  const mime = (file.mimetype || "").toLowerCase();
  return ALLOWED_EXTENSIONS.has(ext) && ALLOWED_MIME_TYPES.has(mime);
}
function removeIfExists(filePath) {
  try { if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (_) {}
}
function clientIp(req) {
  const fwd = (req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return fwd || req.socket.remoteAddress || "unknown";
}
function hashIp(req) {
  return crypto.createHash("sha256").update(IP_SALT + clientIp(req)).digest("hex").slice(0, 16);
}
// Browser fingerprint hash — a second, IP-independent ban signal. A MAC address
// is NOT obtainable by a web server, so this is the closest durable identifier;
// it is imperfect (another browser/incognito/spoofing defeats it).
function fpHash(fp) {
  if (!fp || typeof fp !== "string") return "";
  return crypto.createHash("sha256").update(IP_SALT + "fp:" + fp).digest("hex").slice(0, 16);
}
function parseTags(raw) {
  return safeString(raw, 200).toLowerCase().split(",")
    .map((t) => t.trim().replace(/[^a-z0-9\-]/g, "")).filter(Boolean).slice(0, 8);
}

const rateBuckets = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const arr = (rateBuckets.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) { rateBuckets.set(key, arr); return false; }
  arr.push(now); rateBuckets.set(key, arr); return true;
}
function pruneRateBuckets() {
  const now = Date.now();
  for (const [key, arr] of rateBuckets) {
    const kept = arr.filter((t) => now - t < RATE_WINDOW_MS);
    if (kept.length === 0) rateBuckets.delete(key); else rateBuckets.set(key, kept);
  }
}

function loadList(file) {
  try {
    return fs.readFileSync(file, "utf8").split(/\r?\n/)
      .map((s) => s.trim().toLowerCase()).filter((s) => s && !s.startsWith("#"));
  } catch (_) { return []; }
}
function appendLine(file, line) {
  try { fs.appendFileSync(file, line + "\n", "utf8"); } catch (_) {}
}
function sha256File(p) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash("sha256");
    const s = fs.createReadStream(p);
    s.on("error", reject); s.on("data", (d) => h.update(d)); s.on("end", () => resolve(h.digest("hex")));
  });
}
function firstBlockedWord(text) {
  const t = (text || "").toLowerCase();
  return DEFAULT_BLOCKED_TERMS.concat(loadList(WORD_BLOCKLIST_FILE)).find((w) => w && t.includes(w)) || null;
}
function isBanned(hash) { return loadList(IP_BANLIST_FILE).includes((hash || "").toLowerCase()); }
function banHash(hash) {
  if (!hash || isBanned(hash)) return;
  appendLine(IP_BANLIST_FILE, hash.toLowerCase());
  modLog(`banned uploader hash: ${hash}`);
}
// A perceptual hash of a solid-color frame collides broadly; don't denylist those.
function isTrivialPhash(ph) { return !ph || /^(0{16}|f{16})$/i.test(ph); }
function isPhashBlocked(ph) { return !isTrivialPhash(ph) && loadList(PHASH_BLOCKLIST_FILE).includes(ph.toLowerCase()); }

function modLog(line) {
  appendLine(MOD_LOG_FILE, `${new Date().toISOString()} ${line}`);
  console.log(`[moderation] ${line}`);
}

// Delete a video's file + thumbnail + DB row.
function removeVideo(id, reason) {
  const row = db.getVideo(id);
  if (!row) return false;
  removeIfExists(path.join(VIDEO_DIR, row.stored_name || ""));
  removeIfExists(path.join(THUMB_DIR, row.thumb_name || ""));
  db.deleteVideo(id);
  modLog(`removed ${id} (${reason})`);
  return true;
}

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) { res.status(503).json({ error: "Admin API disabled (set ADMIN_KEY to enable)." }); return; }
  const supplied = req.headers["x-admin-key"] || "";
  if (typeof supplied !== "string" || supplied.length !== ADMIN_KEY.length ||
      !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(ADMIN_KEY))) {
    res.status(403).json({ error: "Forbidden." }); return;
  }
  next();
}

// ---------------------------------------------------------------------------
// Malware scanning: ClamAV (cross-platform) preferred, else Windows Defender.
// ---------------------------------------------------------------------------
let _hasClam = null;
function hasClamAV() {
  if (_hasClam === null) {
    _hasClam = ["clamdscan", "clamscan"].some((c) => {
      try { return spawnSync(c, ["--version"], { windowsHide: true }).status === 0; } catch (_) { return false; }
    });
  }
  return _hasClam;
}
function scanWithClamAV(filePath) {
  return new Promise((resolve) => {
    const bin = (() => { try { return spawnSync("clamdscan", ["--version"], { windowsHide: true }).status === 0 ? "clamdscan" : "clamscan"; } catch (_) { return "clamscan"; } })();
    let out = "";
    const child = spawn(bin, ["--no-summary", "--stdout", filePath], { windowsHide: true });
    child.stdout.on("data", (c) => { out += c.toString(); });
    child.stderr.on("data", (c) => { out += c.toString(); });
    child.on("error", (err) => resolve({ clean: false, threatDetected: false, scanner: "clamav", reason: `Scanner error: ${err.message}` }));
    child.on("close", (code) => {
      if (code === 0) resolve({ clean: true, threatDetected: false, scanner: "clamav", reason: "No threats found" });
      else if (code === 1) resolve({ clean: false, threatDetected: true, scanner: "clamav", reason: "Threat detected", details: safeString(out, 400) });
      else resolve({ clean: false, threatDetected: false, scanner: "clamav", reason: `Scanner exited with code ${code}`, details: safeString(out, 400) });
    });
  });
}
function absoluteDefenderPath() {
  const candidates = [
    "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
    "C:\\Program Files\\Microsoft Defender\\MpCmdRun.exe",
    "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform",
  ];
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    if (candidate.toLowerCase().endsWith(".exe")) return candidate;
    try {
      const children = fs.readdirSync(candidate, { withFileTypes: true })
        .filter((e) => e.isDirectory()).map((e) => e.name).sort().reverse();
      for (const v of children) {
        const exe = path.join(candidate, v, "MpCmdRun.exe");
        if (fs.existsSync(exe)) return exe;
      }
    } catch (_) {}
  }
  return null;
}
function scanWithDefender(filePath) {
  const mpCmdRun = absoluteDefenderPath();
  if (!mpCmdRun) return Promise.resolve({ clean: false, threatDetected: false, scanner: "windows-defender", reason: "Windows Defender scanner executable not found" });
  return new Promise((resolve) => {
    let output = "";
    const child = spawn(mpCmdRun, ["-Scan", "-ScanType", "3", "-File", filePath, "-DisableRemediation"], { windowsHide: true });
    child.stdout.on("data", (c) => { output += c.toString(); });
    child.stderr.on("data", (c) => { output += c.toString(); });
    child.on("error", (err) => resolve({ clean: false, threatDetected: false, scanner: "windows-defender", reason: `Scanner error: ${err.message}` }));
    child.on("close", (code) => {
      if (code === 0) resolve({ clean: true, threatDetected: false, scanner: "windows-defender", reason: "No threats found" });
      else if (code === 2) resolve({ clean: false, threatDetected: true, scanner: "windows-defender", reason: "Threat detected by scanner", details: safeString(output, 400) });
      else resolve({ clean: false, threatDetected: false, scanner: "windows-defender", reason: `Scanner exited with code ${code}`, details: safeString(output, 400) });
    });
  });
}
const MALWARE_SCAN_DISABLED = process.env.MALWARE_SCAN === "off";
function scanForMalware(filePath) {
  if (MALWARE_SCAN_DISABLED) return Promise.resolve({ clean: true, threatDetected: false, scanner: "disabled", reason: "scanning disabled" });
  return hasClamAV() ? scanWithClamAV(filePath) : scanWithDefender(filePath);
}

function looksLikeVideo(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(16);
    fs.readSync(fd, buf, 0, 16, 0);
    if (buf.slice(4, 8).toString("latin1") === "ftyp") return true;
    if (buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3) return true;
    if (buf.slice(0, 4).toString("latin1") === "RIFF" && buf.slice(8, 12).toString("latin1") === "AVI ") return true;
    const atom = buf.slice(4, 8).toString("latin1");
    if (["moov", "mdat", "free", "wide"].includes(atom)) return true;
    return false;
  } catch (_) { return false; } finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch (_) {} } }
}
function ffprobeCheck(filePath) {
  return new Promise((resolve) => {
    let out = "";
    let child;
    try {
      child = spawn("ffprobe", ["-v", "error", "-select_streams", "v:0",
        "-show_entries", "stream=codec_type:format=duration", "-of", "json", filePath], { windowsHide: true });
    } catch (_) { resolve({ ok: true, available: false }); return; }
    child.on("error", () => resolve({ ok: true, available: false }));
    child.stdout.on("data", (c) => { out += c.toString(); });
    child.on("close", (code) => {
      if (code !== 0) { resolve({ ok: false, available: true, reason: "Not a valid/decodable video." }); return; }
      let hasVideo = false, duration = 0;
      try { const j = JSON.parse(out); hasVideo = Array.isArray(j.streams) && j.streams.some((s) => s.codec_type === "video"); duration = Number(j.format && j.format.duration) || 0; } catch (_) {}
      if (!hasVideo) { resolve({ ok: false, available: true, reason: "No video stream found." }); return; }
      if (duration > MAX_DURATION_SEC) { resolve({ ok: false, available: true, reason: `Video too long (max ${MAX_DURATION_SEC}s for clips).` }); return; }
      resolve({ ok: true, available: true });
    });
  });
}
function externalContentScan(filePath) {
  return new Promise((resolve) => {
    if (!CONTENT_SCAN_CMD) { resolve({ ok: true, ran: false }); return; }
    const parts = CONTENT_SCAN_CMD.split(" ").filter(Boolean);
    let child;
    try { child = spawn(parts[0], [...parts.slice(1), filePath], { windowsHide: true }); }
    catch (_) { resolve({ ok: false, ran: true, reason: "Content scanner failed to start." }); return; }
    child.on("error", () => resolve({ ok: false, ran: true, reason: "Content scanner error." }));
    child.on("close", (code) => resolve(code === 0 ? { ok: true, ran: true } : { ok: false, ran: true, reason: "Rejected by content scanner." }));
  });
}

function publicVideoShape(row) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    originalFileName: row.original_name,
    sizeBytes: row.size_bytes,
    uploadedAt: row.uploaded_at,
    expiresAt: row.expires_at,
    views: row.views || 0,
    tags: row.tags ? row.tags.split(",").filter(Boolean) : [],
    reportCount: db.reportCount(row.id),
    thumbUrl: row.thumb_name ? `/thumbs/${encodeURIComponent(row.thumb_name)}` : null,
    videoUrl: `/videos/${encodeURIComponent(row.stored_name)}`,
  };
}

function pruneExpiredVideos() {
  for (const row of db.expiredRows(Date.now())) {
    removeIfExists(path.join(VIDEO_DIR, row.stored_name || ""));
    removeIfExists(path.join(THUMB_DIR, row.thumb_name || ""));
    db.deleteVideo(row.id);
  }
}

const upload = multer({
  dest: TMP_DIR,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (_, file, cb) => {
    if (!isAllowedUpload(file)) { cb(new Error("Only common video file types are allowed.")); return; }
    cb(null, true);
  },
});

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Content-Security-Policy",
    "default-src 'self'; media-src 'self'; img-src 'self' data:; " +
    "style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; " +
    "base-uri 'none'; frame-ancestors 'self'");
  next();
});
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/videos", express.static(VIDEO_DIR));
app.use("/thumbs", express.static(THUMB_DIR));

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
app.get("/api/config", (req, res) => {
  res.json({
    maxUploadMb: Math.floor(MAX_FILE_SIZE / (1024 * 1024)),
    allowedExtensions: Array.from(ALLOWED_EXTENSIONS),
    retentionHours: DEFAULT_RETENTION_HOURS,
    retentionOptions: ALLOWED_RETENTION_HOURS,
    requireApproval: REQUIRE_APPROVAL,
    powRequired: POW_REQUIRED,
    pageSize: PAGE_SIZE,
  });
});

app.get("/api/pow/challenge", (req, res) => res.json(pow.generateChallenge()));

app.get("/api/tags", (req, res) => res.json({ tags: db.allTags() }));

app.get("/api/videos", (req, res) => {
  pruneExpiredVideos();
  const page = Math.max(0, parseInt(req.query.page, 10) || 0);
  const q = safeString(req.query.q, 100);
  const tag = safeString(req.query.tag, 40).toLowerCase();
  const { rows, total } = db.listPublic({ q, tag, limit: PAGE_SIZE, offset: page * PAGE_SIZE });
  res.json({ videos: rows.map(publicVideoShape), total, page, pageSize: PAGE_SIZE });
});

app.get("/api/videos/:id", (req, res) => {
  pruneExpiredVideos();
  const row = db.getVideo(req.params.id);
  if (!row || row.approved === 0) { res.status(404).json({ error: "Video not found." }); return; }
  db.incrementViews(row.id);
  row.views = (row.views || 0) + 1;
  res.json({ video: publicVideoShape(row) });
});

// Minimal shareable embed player.
app.get("/embed/:id", (req, res) => {
  const row = db.getVideo(req.params.id);
  if (!row || row.approved === 0) { res.status(404).send("Not found"); return; }
  const src = `/videos/${encodeURIComponent(row.stored_name)}`;
  const poster = row.thumb_name ? `/thumbs/${encodeURIComponent(row.thumb_name)}` : "";
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html><meta charset="utf-8"><title>VideoTub</title>` +
    `<style>html,body{margin:0;background:#000;height:100%}video{width:100%;height:100%}</style>` +
    `<video src="${src}" ${poster ? `poster="${poster}"` : ""} controls autoplay playsinline></video>`);
});

app.post("/api/upload", (req, res, next) => {
  if (isBanned(hashIp(req))) { res.status(403).json({ error: "Uploads from this source are not permitted." }); return; }
  if (!rateLimit(`up:${hashIp(req)}`, UPLOAD_RATE_MAX, RATE_WINDOW_MS)) { res.status(429).json({ error: "Too many uploads. Please wait and try again." }); return; }
  next();
}, upload.single("video"), async (req, res) => {
  if (!req.file) { res.status(400).json({ error: "No file was uploaded." }); return; }

  if (POW_REQUIRED) {
    const powResult = pow.verify(req.body && req.body.powChallenge, req.body && req.body.powNonce);
    if (!powResult.valid) { removeIfExists(req.file.path); res.status(403).json({ error: "Proof-of-work required. " + (powResult.error || "") }); return; }
  }
  if (!isAllowedUpload(req.file)) { removeIfExists(req.file.path); res.status(400).json({ error: "Only common video file types are allowed." }); return; }

  const uploaderFpHash = fpHash(req.body && req.body.fp);
  if (uploaderFpHash && isBanned(uploaderFpHash)) { removeIfExists(req.file.path); res.status(403).json({ error: "Uploads from this device are not permitted." }); return; }

  const uploadedAt = Date.now();
  let retentionHours = parseInt(req.body && req.body.retentionHours, 10);
  if (!ALLOWED_RETENTION_HOURS.includes(retentionHours)) retentionHours = DEFAULT_RETENTION_HOURS;
  const expiresAt = uploadedAt + retentionHours * 60 * 60 * 1000;
  const id = crypto.randomUUID();
  let ext = extensionFor(req.file.originalname);
  const titleBase = path.basename(req.file.originalname, ext);
  const title = safeString(req.body.title || titleBase, 100) || "Untitled video";
  const description = safeString(req.body.description || "", 800);
  const tags = parseTags(req.body && req.body.tags);

  const badWord = firstBlockedWord(`${title} ${description} ${req.file.originalname} ${tags.join(" ")}`);
  if (badWord) { removeIfExists(req.file.path); modLog(`rejected upload from ${hashIp(req)}: blocked term`); res.status(400).json({ error: "Upload rejected: title, tags, or description contains a blocked term." }); return; }

  if (!looksLikeVideo(req.file.path)) { removeIfExists(req.file.path); modLog(`rejected upload from ${hashIp(req)}: not a real video`); res.status(400).json({ error: "Upload rejected: file is not a valid video." }); return; }

  let fileHash = "";
  try { fileHash = await sha256File(req.file.path); } catch (_) {}
  if (fileHash && loadList(HASH_BLOCKLIST_FILE).includes(fileHash.toLowerCase())) { removeIfExists(req.file.path); modLog(`BLOCKED upload from ${hashIp(req)}: hash on denylist`); res.status(403).json({ error: "Upload rejected: this file is not allowed." }); return; }

  const probe = await ffprobeCheck(req.file.path);
  if (!probe.ok) { removeIfExists(req.file.path); modLog(`rejected upload from ${hashIp(req)}: ${probe.reason}`); res.status(400).json({ error: `Upload rejected: ${probe.reason}` }); return; }

  // Perceptual hash — block near-duplicates of previously removed content.
  const phash = await media.perceptualHash(req.file.path);
  if (isPhashBlocked(phash)) { removeIfExists(req.file.path); modLog(`BLOCKED upload from ${hashIp(req)}: perceptual hash on denylist`); res.status(403).json({ error: "Upload rejected: this content is not allowed." }); return; }

  const contentScan = await externalContentScan(req.file.path);
  if (!contentScan.ok) { removeIfExists(req.file.path); modLog(`rejected upload from ${hashIp(req)}: ${contentScan.reason || "content scan"}`); res.status(400).json({ error: "Upload rejected: content check failed." }); return; }

  const scanResult = await scanForMalware(req.file.path);
  if (!scanResult.clean) {
    if (scanResult.threatDetected) { removeIfExists(req.file.path); res.status(400).json({ error: "Upload blocked: malware threat detected.", scanner: scanResult.scanner, details: scanResult.reason }); return; }
    if (STRICT_SCANNER) { removeIfExists(req.file.path); res.status(400).json({ error: "Upload blocked by malware scanner.", scanner: scanResult.scanner, details: scanResult.reason }); return; }
  }

  // Store: transcode to web-playable mp4 when the source isn't browser-safe.
  let storedName = `${id}${ext}`;
  let finalPath = path.join(VIDEO_DIR, storedName);
  try {
    if (!media.isWebPlayable(ext) && media.hasFfmpeg()) {
      const mp4Path = path.join(VIDEO_DIR, `${id}.mp4`);
      const out = await media.transcodeToMp4(req.file.path, mp4Path);
      if (out) { storedName = `${id}.mp4`; finalPath = mp4Path; ext = ".mp4"; removeIfExists(req.file.path); }
      else { fs.renameSync(req.file.path, finalPath); } // transcode failed — keep original
    } else {
      fs.renameSync(req.file.path, finalPath);
    }
  } catch (err) { removeIfExists(req.file.path); res.status(500).json({ error: "Failed to store uploaded file." }); return; }

  // Thumbnail (best-effort).
  let thumbName = "";
  try {
    const t = await media.makeThumbnail(finalPath, path.join(THUMB_DIR, `${id}.jpg`));
    if (t) thumbName = `${id}.jpg`;
  } catch (_) {}

  const deleteToken = crypto.randomBytes(24).toString("hex");
  const deleteTokenHash = crypto.createHash("sha256").update(deleteToken).digest("hex");

  db.insertVideo({
    id, title, description,
    original_name: req.file.originalname, stored_name: storedName, thumb_name: thumbName,
    mime: req.file.mimetype, size_bytes: fs.existsSync(finalPath) ? fs.statSync(finalPath).size : req.file.size,
    uploaded_at: uploadedAt, expires_at: expiresAt,
    file_hash: fileHash, phash,
    uploader_ip_hash: hashIp(req), uploader_fp_hash: uploaderFpHash,
    delete_token_hash: deleteTokenHash,
    scanner: scanResult.scanner, scan_result: scanResult.reason,
    approved: REQUIRE_APPROVAL ? 0 : 1,
    tags: tags.join(","),
  });

  res.status(201).json({ ok: true, pending: REQUIRE_APPROVAL, video: publicVideoShape(db.getVideo(id)), deleteToken });
});

app.post("/api/videos/:id/report", (req, res) => {
  if (!rateLimit(`rep:${hashIp(req)}`, REPORT_RATE_MAX, RATE_WINDOW_MS)) { res.status(429).json({ error: "Too many reports. Please wait and try again." }); return; }
  const row = db.getVideo(req.params.id);
  if (!row) { res.status(404).json({ error: "Video not found." }); return; }
  const reason = safeString(req.body && req.body.reason, 300) || "unspecified";
  const count = db.addReport(row.id, reason, hashIp(req), Date.now());
  modLog(`report on ${row.id} (${count}/${REPORT_AUTO_REMOVE}): ${reason}`);
  if (count >= REPORT_AUTO_REMOVE) {
    removeVideo(row.id, `auto-removed after ${count} reports`);
    res.json({ ok: true, removed: true, message: "Video removed after reaching the report threshold." });
    return;
  }
  res.json({ ok: true, removed: false, reportCount: count });
});

app.delete("/api/videos/:id", (req, res) => {
  const token = (req.body && req.body.token) || req.query.token || "";
  if (typeof token !== "string" || !token) { res.status(400).json({ error: "A delete token is required." }); return; }
  const row = db.getVideo(req.params.id);
  if (!row) { res.status(404).json({ error: "Video not found." }); return; }
  const suppliedHash = crypto.createHash("sha256").update(token).digest("hex");
  const stored = row.delete_token_hash || "";
  const ok = stored.length === suppliedHash.length && crypto.timingSafeEqual(Buffer.from(suppliedHash), Buffer.from(stored));
  if (!ok) { res.status(403).json({ error: "Invalid delete token." }); return; }
  removeVideo(row.id, "deleted by uploader");
  res.json({ ok: true, removed: true });
});

// ---------------------------------------------------------------------------
// Admin API
// ---------------------------------------------------------------------------
app.get("/api/admin/videos", requireAdmin, (req, res) => {
  pruneExpiredVideos();
  const rows = db.listAll().map((r) => ({
    id: r.id, title: r.title, originalFileName: r.original_name, sizeBytes: r.size_bytes,
    uploadedAt: r.uploaded_at, expiresAt: r.expires_at, approved: r.approved !== 0,
    views: r.views || 0, fileHash: r.file_hash, phash: r.phash,
    uploaderIpHash: r.uploader_ip_hash, uploaderFpHash: r.uploader_fp_hash,
    thumbUrl: r.thumb_name ? `/thumbs/${encodeURIComponent(r.thumb_name)}` : null,
    videoUrl: `/videos/${encodeURIComponent(r.stored_name)}`,
    reportCount: db.reportCount(r.id), reports: db.reportsFor(r.id),
  }));
  res.json({ videos: rows });
});

app.delete("/api/admin/videos/:id", requireAdmin, (req, res) => {
  const row = db.getVideo(req.params.id);
  const hash = row && row.file_hash, phash = row && row.phash;
  const uploaderIp = row && row.uploader_ip_hash, uploaderFp = row && row.uploader_fp_hash;
  if (!removeVideo(req.params.id, "removed by admin")) { res.status(404).json({ error: "Video not found." }); return; }
  const doBlock = req.query.block === "1" || (req.body && req.body.block);
  const doBan = req.query.ban === "1" || (req.body && req.body.ban);
  if (doBlock) {
    if (/^[a-f0-9]{64}$/.test(hash || "")) { appendLine(HASH_BLOCKLIST_FILE, hash); modLog(`admin blocked hash: ${hash}`); }
    if (!isTrivialPhash(phash)) { appendLine(PHASH_BLOCKLIST_FILE, phash); modLog(`admin blocked phash: ${phash}`); }
  }
  if (doBan) { if (uploaderIp) banHash(uploaderIp); if (uploaderFp) banHash(uploaderFp); }
  res.json({ ok: true, removed: true, blocked: !!doBlock, banned: !!doBan });
});

app.post("/api/admin/videos/:id/approve", requireAdmin, (req, res) => {
  if (!db.approve(req.params.id)) { res.status(404).json({ error: "Video not found." }); return; }
  modLog(`approved ${req.params.id}`);
  res.json({ ok: true, approved: true });
});

app.post("/api/admin/ban", requireAdmin, (req, res) => {
  const hash = safeString(req.body && req.body.ipHash, 32).toLowerCase();
  if (!/^[a-f0-9]{8,}$/.test(hash)) { res.status(400).json({ error: "Provide a valid uploader hash." }); return; }
  banHash(hash);
  res.json({ ok: true });
});

app.post("/api/admin/blocklist", requireAdmin, (req, res) => {
  const hash = safeString(req.body && req.body.hash, 64).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hash)) { res.status(400).json({ error: "Provide a valid sha256 hex hash." }); return; }
  appendLine(HASH_BLOCKLIST_FILE, hash);
  modLog(`admin added hash to denylist: ${hash}`);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
  if (req && req.file && req.file.path) removeIfExists(req.file.path);
  if (err && err.code === "LIMIT_FILE_SIZE") { res.status(400).json({ error: `File too large. Max allowed size is ${Math.floor(MAX_FILE_SIZE / (1024 * 1024))} MB.` }); return; }
  if (err) { res.status(400).json({ error: err.message || "Upload failed." }); return; }
  next();
});

app.get("*", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));

pruneExpiredVideos();
setInterval(() => { pruneExpiredVideos(); pruneRateBuckets(); }, CLEANUP_INTERVAL_MS);

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`VideoTub running on http://localhost:${PORT}`);
    console.log(`  malware scanner: ${hasClamAV() ? "ClamAV" : "Windows Defender (if present)"}; ffmpeg: ${media.hasFfmpeg() ? "yes" : "no (thumbnails/transcode/phash disabled)"}`);
  });
}

module.exports = app; // for tests

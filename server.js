const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");

const express = require("express");
const multer = require("multer");

const pow = require("./pow");
const POW_REQUIRED = process.env.POW_DISABLED !== "true"; // on by default

const app = express();

const PORT = Number(process.env.PORT || 3000);
const VIDEO_TTL_MS = 24 * 60 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 250);
const MAX_FILE_SIZE = Math.max(1, Math.floor(MAX_UPLOAD_MB)) * 1024 * 1024;

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const DATA_DIR = path.join(ROOT, "data");
const TMP_DIR = path.join(ROOT, "tmp");
const VIDEO_DIR = path.join(ROOT, "videos");
const DB_FILE = path.join(DATA_DIR, "videos.json");
const STRICT_SCANNER = process.env.ALLOW_UNSCANNED_UPLOADS !== "true";

// --- Moderation / rate limiting / protection config -------------------------
const ADMIN_KEY = process.env.ADMIN_KEY || "";                 // enables /api/admin/* when set
const REPORT_AUTO_REMOVE = Math.max(1, Number(process.env.REPORT_AUTO_REMOVE || 3));
const UPLOAD_RATE_MAX = Math.max(1, Number(process.env.UPLOAD_RATE_MAX || 5));
const REPORT_RATE_MAX = Math.max(1, Number(process.env.REPORT_RATE_MAX || 20));
const RATE_WINDOW_MS = Math.max(1000, Number(process.env.RATE_WINDOW_MS || 10 * 60 * 1000));
const HASH_BLOCKLIST_FILE = path.join(DATA_DIR, "hash-blocklist.txt");   // one sha256 hex per line
const WORD_BLOCKLIST_FILE = path.join(DATA_DIR, "word-blocklist.txt");   // one term per line
const IP_BANLIST_FILE = path.join(DATA_DIR, "ip-banlist.txt");           // one uploader ip-hash per line
const MOD_LOG_FILE = path.join(DATA_DIR, "moderation.log");

// Per-process salt so uploader IPs are stored as unlinkable hashes, not plaintext.
const IP_SALT = crypto.randomBytes(16).toString("hex");

// --- Proactive content controls ---------------------------------------------
// Clips/memes are short: cap duration to keep out movies/long-form (and the
// piracy/abuse that rides with it). Requires ffprobe on PATH; skipped if absent.
const MAX_DURATION_SEC = Math.max(1, Number(process.env.MAX_DURATION_SEC || 900)); // 15 min
// Pre-publish moderation: when true, uploads are held (not listed/watchable)
// until an admin approves them. The strongest guard against harmful content
// going live on a shared instance.
const REQUIRE_APPROVAL = process.env.REQUIRE_APPROVAL === "true";
// Optional external content scanner (e.g. an NSFW/ML classifier or cloud API
// wrapper). Given the file path as its last arg; exit code 0 = allow, non-zero
// = reject. Empty = disabled.
const CONTENT_SCAN_CMD = process.env.CONTENT_SCAN_CMD || "";
// A small built-in seed denylist of terms that clearly signal illegal content,
// always checked in addition to data/word-blocklist.txt.
const DEFAULT_BLOCKED_TERMS = ["childporn", "child porn", "cp video", "underage", "r@pe"];

// Magic-byte signatures so a non-video renamed `.mp4` is rejected (extension and
// client MIME are both spoofable; this checks the actual bytes).
function looksLikeVideo(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(16);
    fs.readSync(fd, buf, 0, 16, 0);
    // MP4 / MOV / M4V: "ftyp" at offset 4
    if (buf.slice(4, 8).toString("latin1") === "ftyp") return true;
    // Matroska / WebM: EBML header 1A 45 DF A3
    if (buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3) return true;
    // AVI: "RIFF" .... "AVI "
    if (buf.slice(0, 4).toString("latin1") === "RIFF" && buf.slice(8, 12).toString("latin1") === "AVI ") return true;
    // Some MPEG/MOV variants start with 00 00 00 xx ftyp handled above; also
    // accept a leading "moov"/"mdat" atom just in case.
    const atom = buf.slice(4, 8).toString("latin1");
    if (atom === "moov" || atom === "mdat" || atom === "free" || atom === "wide") return true;
    return false;
  } catch (_) {
    return false;
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch (_) {} }
  }
}

// Validate with ffprobe when available: must have a video stream, and duration
// must be within MAX_DURATION_SEC. Returns {ok, reason, available}.
function ffprobeCheck(filePath) {
  return new Promise((resolve) => {
    let out = "";
    let child;
    try {
      child = spawn("ffprobe", [
        "-v", "error", "-select_streams", "v:0",
        "-show_entries", "stream=codec_type:format=duration",
        "-of", "json", filePath,
      ], { windowsHide: true });
    } catch (_) {
      resolve({ ok: true, available: false, reason: "ffprobe not available" });
      return;
    }
    child.on("error", () => resolve({ ok: true, available: false, reason: "ffprobe not available" }));
    child.stdout.on("data", (c) => { out += c.toString(); });
    child.on("close", (code) => {
      if (code !== 0) { resolve({ ok: false, available: true, reason: "Not a valid/decodable video." }); return; }
      let hasVideo = false;
      let duration = 0;
      try {
        const j = JSON.parse(out);
        hasVideo = Array.isArray(j.streams) && j.streams.some((s) => s.codec_type === "video");
        duration = Number(j.format && j.format.duration) || 0;
      } catch (_) {}
      if (!hasVideo) { resolve({ ok: false, available: true, reason: "No video stream found." }); return; }
      if (duration > MAX_DURATION_SEC) {
        resolve({ ok: false, available: true, reason: `Video too long (max ${MAX_DURATION_SEC}s for clips).` });
        return;
      }
      resolve({ ok: true, available: true, reason: "ok" });
    });
  });
}

// Optional operator-supplied content scanner. Exit 0 = allow, non-zero = reject.
function externalContentScan(filePath) {
  return new Promise((resolve) => {
    if (!CONTENT_SCAN_CMD) { resolve({ ok: true, ran: false }); return; }
    const parts = CONTENT_SCAN_CMD.split(" ").filter(Boolean);
    let child;
    try {
      child = spawn(parts[0], [...parts.slice(1), filePath], { windowsHide: true });
    } catch (err) {
      // Fail closed: if the operator configured a scanner and it can't run, reject.
      resolve({ ok: false, ran: true, reason: "Content scanner failed to start." });
      return;
    }
    child.on("error", () => resolve({ ok: false, ran: true, reason: "Content scanner error." }));
    child.on("close", (code) => {
      if (code === 0) resolve({ ok: true, ran: true });
      else resolve({ ok: false, ran: true, reason: "Rejected by content scanner." });
    });
  });
}

const ALLOWED_EXTENSIONS = new Set([".mp4", ".webm", ".mkv", ".mov", ".avi", ".m4v"]);
const ALLOWED_MIME_TYPES = new Set([
  "video/mp4",
  "video/webm",
  "video/x-matroska",
  "video/quicktime",
  "video/x-msvideo",
  "video/x-m4v",
]);

for (const dir of [DATA_DIR, TMP_DIR, VIDEO_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, "[]", "utf8");
}

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

function readDb() {
  try {
    const raw = fs.readFileSync(DB_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
}

function writeDb(rows) {
  const payload = JSON.stringify(rows, null, 2);
  fs.writeFileSync(DB_FILE, payload, "utf8");
}

function removeIfExists(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch (_) {}
}

function clientIp(req) {
  const fwd = (req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return fwd || req.socket.remoteAddress || "unknown";
}

function hashIp(req) {
  return crypto.createHash("sha256").update(IP_SALT + clientIp(req)).digest("hex").slice(0, 16);
}

// Browser fingerprint hash — a second, IP-independent ban signal. NOTE: a MAC
// address is NOT obtainable by a web server (it never leaves the client's LAN),
// so this is the closest durable identifier available. It is imperfect
// (defeated by another browser/incognito/spoofing) and privacy-sensitive.
function fpHash(fp) {
  if (!fp || typeof fp !== "string") return "";
  return crypto.createHash("sha256").update(IP_SALT + "fp:" + fp).digest("hex").slice(0, 16);
}

// In-memory sliding-window rate limiter (no external dep).
const rateBuckets = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const arr = (rateBuckets.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) {
    rateBuckets.set(key, arr);
    return false;
  }
  arr.push(now);
  rateBuckets.set(key, arr);
  return true;
}
function pruneRateBuckets() {
  const now = Date.now();
  for (const [key, arr] of rateBuckets) {
    const kept = arr.filter((t) => now - t < RATE_WINDOW_MS);
    if (kept.length === 0) rateBuckets.delete(key);
    else rateBuckets.set(key, kept);
  }
}

// Operator-maintained denylists. Reloaded from disk on each read so an admin can
// update them live without a restart.
function loadList(file) {
  try {
    return fs
      .readFileSync(file, "utf8")
      .split(/\r?\n/)
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s && !s.startsWith("#"));
  } catch (_) {
    return [];
  }
}

// SHA-256 of the uploaded file (streamed, so a 250 MB file isn't buffered).
function sha256File(p) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash("sha256");
    const s = fs.createReadStream(p);
    s.on("error", reject);
    s.on("data", (d) => h.update(d));
    s.on("end", () => resolve(h.digest("hex")));
  });
}

function firstBlockedWord(text) {
  const t = (text || "").toLowerCase();
  const terms = DEFAULT_BLOCKED_TERMS.concat(loadList(WORD_BLOCKLIST_FILE));
  return terms.find((w) => w && t.includes(w)) || null;
}

function isBanned(ipHash) {
  return loadList(IP_BANLIST_FILE).includes((ipHash || "").toLowerCase());
}

function banIpHash(ipHash) {
  if (!ipHash || isBanned(ipHash)) return;
  try {
    fs.appendFileSync(IP_BANLIST_FILE, ipHash.toLowerCase() + "\n", "utf8");
    modLog(`banned uploader ip-hash: ${ipHash}`);
  } catch (_) {}
}

function modLog(line) {
  try {
    fs.appendFileSync(MOD_LOG_FILE, `${new Date().toISOString()} ${line}\n`, "utf8");
  } catch (_) {}
  console.log(`[moderation] ${line}`);
}

// Delete a video's file + DB row. reason is logged.
function removeVideo(id, reason) {
  const rows = readDb();
  const idx = rows.findIndex((r) => r && r.id === id);
  if (idx === -1) return false;
  removeIfExists(path.join(VIDEO_DIR, rows[idx].storedFileName || ""));
  rows.splice(idx, 1);
  writeDb(rows);
  modLog(`removed ${id} (${reason})`);
  return true;
}

// Admin gate: requires ADMIN_KEY to be configured AND matched via x-admin-key.
function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) {
    res.status(503).json({ error: "Admin API disabled (set ADMIN_KEY to enable)." });
    return;
  }
  const supplied = req.headers["x-admin-key"] || "";
  if (typeof supplied !== "string" || supplied.length !== ADMIN_KEY.length ||
      !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(ADMIN_KEY))) {
    res.status(403).json({ error: "Forbidden." });
    return;
  }
  next();
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
      const children = fs
        .readdirSync(candidate, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name)
        .sort()
        .reverse();
      for (const versionFolder of children) {
        const exePath = path.join(candidate, versionFolder, "MpCmdRun.exe");
        if (fs.existsSync(exePath)) return exePath;
      }
    } catch (_) {}
  }

  return null;
}

function scanWithDefender(filePath) {
  const mpCmdRun = absoluteDefenderPath();
  if (!mpCmdRun) {
    return Promise.resolve({
      clean: false,
      threatDetected: false,
      scanner: "windows-defender",
      reason: "Windows Defender scanner executable not found",
    });
  }

  return new Promise((resolve) => {
    let output = "";
    const child = spawn(mpCmdRun, ["-Scan", "-ScanType", "3", "-File", filePath, "-DisableRemediation"], {
      windowsHide: true,
    });

    child.stdout.on("data", (chunk) => {
      output += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      output += chunk.toString();
    });

    child.on("error", (err) => {
      resolve({
        clean: false,
        threatDetected: false,
        scanner: "windows-defender",
        reason: `Scanner error: ${err.message}`,
      });
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve({
          clean: true,
          threatDetected: false,
          scanner: "windows-defender",
          reason: "No threats found",
        });
        return;
      }

      if (code === 2) {
        resolve({
          clean: false,
          threatDetected: true,
          scanner: "windows-defender",
          reason: "Threat detected by scanner",
          details: safeString(output, 400),
        });
        return;
      }

      resolve({
        clean: false,
        threatDetected: false,
        scanner: "windows-defender",
        reason: `Scanner exited with code ${String(code)}`,
        details: safeString(output, 400),
      });
    });
  });
}

function pruneExpiredVideos() {
  const now = Date.now();
  const rows = readDb();
  if (rows.length === 0) return;

  const remaining = [];
  let changed = false;

  for (const row of rows) {
    if (!row || typeof row !== "object") {
      changed = true;
      continue;
    }

    const expiresAt = Number(row.expiresAt || 0);
    if (expiresAt > 0 && expiresAt <= now) {
      removeIfExists(path.join(VIDEO_DIR, row.storedFileName || ""));
      changed = true;
      continue;
    }

    remaining.push(row);
  }

  if (changed) {
    writeDb(remaining);
  }
}

function publicVideoShape(row) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    originalFileName: row.originalFileName,
    sizeBytes: row.sizeBytes,
    uploadedAt: row.uploadedAt,
    expiresAt: row.expiresAt,
    reportCount: Array.isArray(row.reports) ? row.reports.length : (row.reportCount || 0),
    videoUrl: `/videos/${encodeURIComponent(row.storedFileName)}`,
  };
}

const upload = multer({
  dest: TMP_DIR,
  limits: {
    fileSize: MAX_FILE_SIZE,
  },
  fileFilter: (_, file, cb) => {
    if (!isAllowedUpload(file)) {
      cb(new Error("Only common video file types are allowed."));
      return;
    }
    cb(null, true);
  },
});

// Security headers on every response (incl. served videos + static assets).
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; media-src 'self'; img-src 'self' data:; " +
      "style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; " +
      "base-uri 'none'; frame-ancestors 'self'"
  );
  next();
});

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
// Serve stored videos as attachments-safe inline media; nosniff (set above)
// prevents a mislabeled file from being interpreted as anything but video.
app.use("/videos", express.static(VIDEO_DIR));

app.get("/api/config", (req, res) => {
  res.json({
    maxUploadMb: Math.floor(MAX_FILE_SIZE / (1024 * 1024)),
    allowedExtensions: Array.from(ALLOWED_EXTENSIONS),
    retentionHours: Math.floor(VIDEO_TTL_MS / (60 * 60 * 1000)),
    requireApproval: REQUIRE_APPROVAL,
    powRequired: POW_REQUIRED,
  });
});

// Proof-of-work challenge (anti-bot gate before uploading).
app.get("/api/pow/challenge", (req, res) => {
  res.json(pow.generateChallenge());
});

function isPublic(row) {
  return row && row.approved !== false; // legacy rows (no field) treated as approved
}

app.get("/api/videos", (req, res) => {
  pruneExpiredVideos();
  const rows = readDb()
    .filter(isPublic)
    .sort((a, b) => Number(b.uploadedAt || 0) - Number(a.uploadedAt || 0))
    .map(publicVideoShape);
  res.json({ videos: rows });
});

app.get("/api/videos/:id", (req, res) => {
  pruneExpiredVideos();
  const rows = readDb();
  const found = rows.find((row) => row.id === req.params.id);
  if (!found || !isPublic(found)) {
    res.status(404).json({ error: "Video not found." });
    return;
  }

  res.json({ video: publicVideoShape(found) });
});

app.post("/api/upload", (req, res, next) => {
  // Banned uploaders (by ip-hash) are rejected before the body is accepted.
  if (isBanned(hashIp(req))) {
    res.status(403).json({ error: "Uploads from this source are not permitted." });
    return;
  }
  // Rate limit BEFORE accepting the multipart body, to cap abuse/disk use.
  if (!rateLimit(`up:${hashIp(req)}`, UPLOAD_RATE_MAX, RATE_WINDOW_MS)) {
    res.status(429).json({ error: "Too many uploads. Please wait and try again." });
    return;
  }
  next();
}, upload.single("video"), async (req, res) => {
  if (!req.file) {
    res.status(400).json({ error: "No file was uploaded." });
    return;
  }

  // Proof-of-work gate: reject uploads without a valid solved challenge.
  if (POW_REQUIRED) {
    const powResult = pow.verify(req.body && req.body.powChallenge, req.body && req.body.powNonce);
    if (!powResult.valid) {
      removeIfExists(req.file.path);
      res.status(403).json({ error: "Proof-of-work required. " + (powResult.error || "") });
      return;
    }
  }

  if (!isAllowedUpload(req.file)) {
    removeIfExists(req.file.path);
    res.status(400).json({ error: "Only common video file types are allowed." });
    return;
  }

  const uploadedAt = Date.now();
  const expiresAt = uploadedAt + VIDEO_TTL_MS;
  const id = crypto.randomUUID();
  const ext = extensionFor(req.file.originalname);
  const storedFileName = `${id}${ext}`;
  const finalPath = path.join(VIDEO_DIR, storedFileName);
  const titleBase = path.basename(req.file.originalname, ext);
  const title = safeString(req.body.title || titleBase, 100) || "Untitled video";
  const description = safeString(req.body.description || "", 800);

  // Second ban signal: browser fingerprint (survives IP changes).
  const uploaderFpHash = fpHash(req.body && req.body.fp);
  if (uploaderFpHash && isBanned(uploaderFpHash)) {
    removeIfExists(req.file.path);
    res.status(403).json({ error: "Uploads from this device are not permitted." });
    return;
  }

  // Text moderation: reject titles/descriptions containing denylisted terms.
  const badWord = firstBlockedWord(`${title} ${description} ${req.file.originalname}`);
  if (badWord) {
    removeIfExists(req.file.path);
    modLog(`rejected upload from ${hashIp(req)}: blocked term in metadata`);
    res.status(400).json({ error: "Upload rejected: title or description contains a blocked term." });
    return;
  }

  // Real video validation: reject files whose bytes aren't actually a video
  // container (a non-video renamed .mp4 would otherwise be stored).
  if (!looksLikeVideo(req.file.path)) {
    removeIfExists(req.file.path);
    modLog(`rejected upload from ${hashIp(req)}: not a real video file`);
    res.status(400).json({ error: "Upload rejected: file is not a valid video." });
    return;
  }

  // Content moderation: block known-bad files by SHA-256 hash denylist. This is
  // the hook an operator uses to reject previously-flagged/illegal content
  // (populate data/hash-blocklist.txt with hashes, e.g. from a review or a
  // trusted hash source).
  let fileHash = "";
  try {
    fileHash = await sha256File(req.file.path);
  } catch (_) {}
  if (fileHash && loadList(HASH_BLOCKLIST_FILE).includes(fileHash.toLowerCase())) {
    removeIfExists(req.file.path);
    modLog(`BLOCKED upload from ${hashIp(req)}: hash ${fileHash} on denylist`);
    res.status(403).json({ error: "Upload rejected: this file is not allowed." });
    return;
  }

  // Video sanity + short-clip enforcement (ffprobe; skipped if not installed).
  const probe = await ffprobeCheck(req.file.path);
  if (!probe.ok) {
    removeIfExists(req.file.path);
    modLog(`rejected upload from ${hashIp(req)}: ${probe.reason}`);
    res.status(400).json({ error: `Upload rejected: ${probe.reason}` });
    return;
  }

  // Optional external content scanner (NSFW/ML/cloud) — fail closed if configured.
  const contentScan = await externalContentScan(req.file.path);
  if (!contentScan.ok) {
    removeIfExists(req.file.path);
    modLog(`rejected upload from ${hashIp(req)}: ${contentScan.reason || "content scan"}`);
    res.status(400).json({ error: "Upload rejected: content check failed." });
    return;
  }

  const scanResult = await scanWithDefender(req.file.path);
  if (!scanResult.clean) {
    if (scanResult.threatDetected) {
      removeIfExists(req.file.path);
      res.status(400).json({
        error: "Upload blocked: malware threat detected.",
        scanner: scanResult.scanner,
        details: scanResult.reason,
      });
      return;
    }

    if (STRICT_SCANNER) {
      removeIfExists(req.file.path);
      res.status(400).json({
        error: "Upload blocked by malware scanner.",
        scanner: scanResult.scanner,
        details: scanResult.reason,
      });
      return;
    }
  }

  try {
    fs.renameSync(req.file.path, finalPath);
  } catch (err) {
    removeIfExists(req.file.path);
    res.status(500).json({ error: "Failed to store uploaded file." });
    return;
  }

  // Deletion secret: the uploader gets this once and uses it to delete their own
  // video. Only its hash is stored, so the DB can't be used to delete for them.
  const deleteToken = crypto.randomBytes(24).toString("hex");
  const deleteTokenHash = crypto.createHash("sha256").update(deleteToken).digest("hex");

  const rows = readDb();
  rows.push({
    id,
    title,
    description,
    originalFileName: req.file.originalname,
    storedFileName,
    mimeType: req.file.mimetype,
    sizeBytes: req.file.size,
    uploadedAt,
    expiresAt,
    scanner: scanResult.scanner,
    scanResult: scanResult.reason,
    fileHash,
    uploaderIpHash: hashIp(req),
    uploaderFpHash,
    deleteTokenHash,
    reports: [],
    approved: !REQUIRE_APPROVAL, // held for admin review when approval is required
  });
  writeDb(rows);

  res.status(201).json({
    ok: true,
    pending: REQUIRE_APPROVAL,
    video: publicVideoShape(rows[rows.length - 1]),
    deleteToken, // shown to the uploader once; save it to delete the video
  });
});

// Report a video. After REPORT_AUTO_REMOVE distinct reports it is auto-removed.
app.post("/api/videos/:id/report", (req, res) => {
  if (!rateLimit(`rep:${hashIp(req)}`, REPORT_RATE_MAX, RATE_WINDOW_MS)) {
    res.status(429).json({ error: "Too many reports. Please wait and try again." });
    return;
  }
  const rows = readDb();
  const row = rows.find((r) => r && r.id === req.params.id);
  if (!row) {
    res.status(404).json({ error: "Video not found." });
    return;
  }
  const reason = safeString(req.body && req.body.reason, 300) || "unspecified";
  const reporter = hashIp(req);
  row.reports = Array.isArray(row.reports) ? row.reports : [];
  if (!row.reports.some((rep) => rep.reporter === reporter)) {
    row.reports.push({ reason, reporter, ts: Date.now() });
  }
  const count = row.reports.length;
  modLog(`report on ${row.id} (${count}/${REPORT_AUTO_REMOVE}): ${reason}`);

  if (count >= REPORT_AUTO_REMOVE) {
    writeDb(rows);
    removeVideo(row.id, `auto-removed after ${count} reports`);
    res.json({ ok: true, removed: true, message: "Video removed after reaching the report threshold." });
    return;
  }
  writeDb(rows);
  res.json({ ok: true, removed: false, reportCount: count });
});

// Uploader-initiated deletion using the delete token issued at upload time.
app.delete("/api/videos/:id", (req, res) => {
  const token = (req.body && req.body.token) || req.query.token || "";
  if (typeof token !== "string" || !token) {
    res.status(400).json({ error: "A delete token is required." });
    return;
  }
  const rows = readDb();
  const row = rows.find((r) => r && r.id === req.params.id);
  if (!row) {
    res.status(404).json({ error: "Video not found." });
    return;
  }
  const suppliedHash = crypto.createHash("sha256").update(token).digest("hex");
  const stored = row.deleteTokenHash || "";
  const ok =
    stored.length === suppliedHash.length &&
    crypto.timingSafeEqual(Buffer.from(suppliedHash), Buffer.from(stored));
  if (!ok) {
    res.status(403).json({ error: "Invalid delete token." });
    return;
  }
  removeVideo(row.id, "deleted by uploader");
  res.json({ ok: true, removed: true });
});

// --- Admin moderation API (requires ADMIN_KEY + x-admin-key header) ----------
app.get("/api/admin/videos", requireAdmin, (req, res) => {
  pruneExpiredVideos();
  const rows = readDb().map((r) => ({
    id: r.id,
    title: r.title,
    originalFileName: r.originalFileName,
    sizeBytes: r.sizeBytes,
    uploadedAt: r.uploadedAt,
    expiresAt: r.expiresAt,
    approved: r.approved !== false,
    fileHash: r.fileHash,
    uploaderIpHash: r.uploaderIpHash,
    reportCount: Array.isArray(r.reports) ? r.reports.length : 0,
    reports: Array.isArray(r.reports) ? r.reports : [],
  }));
  res.json({ videos: rows });
});

app.delete("/api/admin/videos/:id", requireAdmin, (req, res) => {
  // Capture hash + uploader before removal so ?block=1 / ?ban=1 can act.
  const row = readDb().find((r) => r && r.id === req.params.id);
  const hash = row && row.fileHash;
  const uploaderIp = row && row.uploaderIpHash;
  const uploaderFp = row && row.uploaderFpHash;
  const removed = removeVideo(req.params.id, "removed by admin");
  if (!removed) {
    res.status(404).json({ error: "Video not found." });
    return;
  }
  const doBlock = req.query.block === "1" || (req.body && req.body.block);
  const doBan = req.query.ban === "1" || (req.body && req.body.ban);
  if (doBlock && /^[a-f0-9]{64}$/.test(hash || "")) {
    try {
      fs.appendFileSync(HASH_BLOCKLIST_FILE, hash + "\n", "utf8");
      modLog(`admin blocked hash on removal: ${hash}`);
    } catch (_) {}
  }
  if (doBan) {
    // Ban both signals so an IP change alone doesn't dodge the ban.
    if (uploaderIp) banIpHash(uploaderIp);
    if (uploaderFp) banIpHash(uploaderFp);
  }
  res.json({ ok: true, removed: true, blocked: !!doBlock, banned: !!doBan });
});

// Approve a held upload (only meaningful when REQUIRE_APPROVAL=true).
app.post("/api/admin/videos/:id/approve", requireAdmin, (req, res) => {
  const rows = readDb();
  const row = rows.find((r) => r && r.id === req.params.id);
  if (!row) {
    res.status(404).json({ error: "Video not found." });
    return;
  }
  row.approved = true;
  writeDb(rows);
  modLog(`approved ${row.id}`);
  res.json({ ok: true, approved: true });
});

// Ban an uploader by ip-hash (from an admin video listing).
app.post("/api/admin/ban", requireAdmin, (req, res) => {
  const ipHash = safeString(req.body && req.body.ipHash, 32).toLowerCase();
  if (!/^[a-f0-9]{8,}$/.test(ipHash)) {
    res.status(400).json({ error: "Provide a valid uploader ip-hash." });
    return;
  }
  banIpHash(ipHash);
  res.json({ ok: true });
});

// Add a SHA-256 hash to the denylist (block a known-bad file from re-upload).
app.post("/api/admin/blocklist", requireAdmin, (req, res) => {
  const hash = safeString(req.body && req.body.hash, 64).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hash)) {
    res.status(400).json({ error: "Provide a valid sha256 hex hash." });
    return;
  }
  try {
    fs.appendFileSync(HASH_BLOCKLIST_FILE, hash + "\n", "utf8");
    modLog(`admin added hash to denylist: ${hash}`);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to update denylist." });
  }
});

app.use((err, req, res, next) => {
  if (req && req.file && req.file.path) {
    removeIfExists(req.file.path);
  }

  if (err && err.code === "LIMIT_FILE_SIZE") {
    res.status(400).json({
      error: `File too large. Max allowed size is ${Math.floor(MAX_FILE_SIZE / (1024 * 1024))} MB.`,
    });
    return;
  }

  if (err) {
    res.status(400).json({ error: err.message || "Upload failed." });
    return;
  }

  next();
});

app.get("*", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

pruneExpiredVideos();
setInterval(() => {
  pruneExpiredVideos();
  pruneRateBuckets();
}, CLEANUP_INTERVAL_MS);

app.listen(PORT, () => {
  console.log(`VideoTub running on http://localhost:${PORT}`);
});

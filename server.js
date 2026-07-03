const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");

const express = require("express");
const multer = require("multer");

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

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use("/videos", express.static(VIDEO_DIR));

app.get("/api/config", (req, res) => {
  res.json({
    maxUploadMb: Math.floor(MAX_FILE_SIZE / (1024 * 1024)),
    allowedExtensions: Array.from(ALLOWED_EXTENSIONS),
    retentionHours: Math.floor(VIDEO_TTL_MS / (60 * 60 * 1000)),
  });
});

app.get("/api/videos", (req, res) => {
  pruneExpiredVideos();
  const rows = readDb()
    .sort((a, b) => Number(b.uploadedAt || 0) - Number(a.uploadedAt || 0))
    .map(publicVideoShape);
  res.json({ videos: rows });
});

app.get("/api/videos/:id", (req, res) => {
  pruneExpiredVideos();
  const rows = readDb();
  const found = rows.find((row) => row.id === req.params.id);
  if (!found) {
    res.status(404).json({ error: "Video not found." });
    return;
  }

  res.json({ video: publicVideoShape(found) });
});

app.post("/api/upload", upload.single("video"), async (req, res) => {
  if (!req.file) {
    res.status(400).json({ error: "No file was uploaded." });
    return;
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
  });
  writeDb(rows);

  res.status(201).json({
    ok: true,
    video: publicVideoShape(rows[rows.length - 1]),
  });
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
setInterval(pruneExpiredVideos, CLEANUP_INTERVAL_MS);

app.listen(PORT, () => {
  console.log(`VideoTub running on http://localhost:${PORT}`);
});

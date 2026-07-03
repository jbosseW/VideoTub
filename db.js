// db.js — SQLite data layer (replaces the JSON-file store).
// Atomic, indexed, and safe under concurrent uploads.

const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

let db;

function init(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  db = new Database(path.join(dataDir, "videotub.db"));
  db.pragma("journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS videos (
      id TEXT PRIMARY KEY,
      title TEXT,
      description TEXT,
      original_name TEXT,
      stored_name TEXT,
      thumb_name TEXT,
      mime TEXT,
      size_bytes INTEGER,
      uploaded_at INTEGER,
      expires_at INTEGER,
      file_hash TEXT,
      phash TEXT,
      uploader_ip_hash TEXT,
      uploader_fp_hash TEXT,
      delete_token_hash TEXT,
      scanner TEXT,
      scan_result TEXT,
      approved INTEGER DEFAULT 1,
      views INTEGER DEFAULT 0,
      tags TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      video_id TEXT,
      reason TEXT,
      reporter TEXT,
      ts INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_videos_uploaded ON videos(uploaded_at);
    CREATE INDEX IF NOT EXISTS idx_videos_expires ON videos(expires_at);
    CREATE INDEX IF NOT EXISTS idx_reports_video ON reports(video_id);
  `);
  return db;
}

function insertVideo(v) {
  db.prepare(`
    INSERT INTO videos (id, title, description, original_name, stored_name, thumb_name,
      mime, size_bytes, uploaded_at, expires_at, file_hash, phash, uploader_ip_hash,
      uploader_fp_hash, delete_token_hash, scanner, scan_result, approved, views, tags)
    VALUES (@id, @title, @description, @original_name, @stored_name, @thumb_name,
      @mime, @size_bytes, @uploaded_at, @expires_at, @file_hash, @phash, @uploader_ip_hash,
      @uploader_fp_hash, @delete_token_hash, @scanner, @scan_result, @approved, 0, @tags)
  `).run(v);
}

function getVideo(id) {
  return db.prepare("SELECT * FROM videos WHERE id = ?").get(id);
}

function reportsFor(id) {
  return db.prepare("SELECT reason, reporter, ts FROM reports WHERE video_id = ? ORDER BY ts").all(id);
}

function reportCount(id) {
  return db.prepare("SELECT COUNT(*) n FROM reports WHERE video_id = ?").get(id).n;
}

// Public listing with optional search + pagination. Approved only.
function listPublic({ q = "", tag = "", limit = 24, offset = 0 } = {}) {
  const where = ["approved = 1"];
  const params = {};
  if (q) { where.push("(title LIKE @q OR description LIKE @q)"); params.q = `%${q}%`; }
  if (tag) { where.push("(',' || tags || ',') LIKE @tag"); params.tag = `%,${tag},%`; }
  const sql = `SELECT * FROM videos WHERE ${where.join(" AND ")}
    ORDER BY uploaded_at DESC LIMIT @limit OFFSET @offset`;
  const rows = db.prepare(sql).all({ ...params, limit: Math.min(100, limit), offset });
  const total = db.prepare(`SELECT COUNT(*) n FROM videos WHERE ${where.join(" AND ")}`).get(params).n;
  return { rows, total };
}

function listAll() {
  return db.prepare("SELECT * FROM videos ORDER BY uploaded_at DESC").all();
}

function deleteVideo(id) {
  const info = db.prepare("DELETE FROM videos WHERE id = ?").run(id);
  db.prepare("DELETE FROM reports WHERE video_id = ?").run(id);
  return info.changes > 0;
}

function addReport(videoId, reason, reporter, ts) {
  // Dedupe by reporter.
  const exists = db.prepare("SELECT 1 FROM reports WHERE video_id = ? AND reporter = ?").get(videoId, reporter);
  if (!exists) db.prepare("INSERT INTO reports (video_id, reason, reporter, ts) VALUES (?,?,?,?)").run(videoId, reason, reporter, ts);
  return reportCount(videoId);
}

function approve(id) {
  return db.prepare("UPDATE videos SET approved = 1 WHERE id = ?").run(id).changes > 0;
}

function incrementViews(id) {
  db.prepare("UPDATE videos SET views = views + 1 WHERE id = ?").run(id);
}

function expiredRows(now) {
  return db.prepare("SELECT * FROM videos WHERE expires_at > 0 AND expires_at <= ?").all(now);
}

function phashExists(phash) {
  if (!phash) return false;
  return !!db.prepare("SELECT 1 FROM videos WHERE phash = ?").get(phash);
}

function allTags() {
  const rows = db.prepare("SELECT tags FROM videos WHERE approved = 1 AND tags != ''").all();
  const set = new Set();
  for (const r of rows) (r.tags || "").split(",").forEach((t) => t && set.add(t.trim()));
  return Array.from(set).sort();
}

module.exports = {
  init, insertVideo, getVideo, reportsFor, reportCount, listPublic, listAll,
  deleteVideo, addReport, approve, incrementViews, expiredRows, phashExists, allTags,
};

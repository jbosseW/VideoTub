// tests/api.test.js — API + moderation coverage for VideoTub.
// Runs the app with PoW + malware scanning disabled and an isolated data dir.

const os = require("os");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "videotub-test-"));
process.env.VIDEOTUB_RUNTIME_DIR = TMP;
process.env.POW_DISABLED = "true";
process.env.MALWARE_SCAN = "off";
process.env.ADMIN_KEY = "test-admin-key";
process.env.REPORT_AUTO_REMOVE = "3";
process.env.UPLOAD_RATE_MAX = "1000"; // don't let rate limiting interfere with functional tests
process.env.REPORT_RATE_MAX = "1000";

const request = require("supertest");
const app = require("../server");

// A minimal but real MP4 header ("....ftypmp42") so looksLikeVideo passes.
const FAKE_MP4 = Buffer.concat([
  Buffer.from([0x00, 0x00, 0x00, 0x18]),
  Buffer.from("ftypmp42"),
  Buffer.from("videotub test payload bytes"),
]);

function upload(fields = {}) {
  const req = request(app).post("/api/upload").field("fp", fields.fp || "fp-default");
  if (fields.ip) req.set("X-Forwarded-For", fields.ip);
  if (fields.title) req.field("title", fields.title);
  if (fields.tags) req.field("tags", fields.tags);
  if (fields.retentionHours) req.field("retentionHours", String(fields.retentionHours));
  return req.attach("video", FAKE_MP4, { filename: "clip.mp4", contentType: "video/mp4" });
}

afterAll(() => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (_) {} });

describe("config + basics", () => {
  test("GET /api/config exposes flags", async () => {
    const res = await request(app).get("/api/config");
    expect(res.status).toBe(200);
    expect(res.body.powRequired).toBe(false);
    expect(res.body.retentionOptions).toEqual([1, 6, 24, 168]);
  });
  test("GET /api/videos is empty + paginated shape", async () => {
    const res = await request(app).get("/api/videos");
    expect(res.body).toMatchObject({ videos: [], total: 0, page: 0 });
  });
  test("security headers present", async () => {
    const res = await request(app).get("/api/config");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["content-security-policy"]).toContain("default-src 'self'");
  });
});

describe("upload + listing", () => {
  test("upload succeeds and returns a delete token", async () => {
    const res = await upload({ title: "My Clip", tags: "games, funny" });
    expect(res.status).toBe(201);
    expect(res.body.ok).toBe(true);
    expect(res.body.deleteToken).toMatch(/^[a-f0-9]{48}$/);
    expect(res.body.video.tags).toEqual(["games", "funny"]);
  });
  test("it appears in the listing and in tags", async () => {
    const list = await request(app).get("/api/videos");
    expect(list.body.total).toBeGreaterThanOrEqual(1);
    const tags = await request(app).get("/api/tags");
    expect(tags.body.tags).toEqual(expect.arrayContaining(["games", "funny"]));
  });
  test("search filters by query", async () => {
    await upload({ title: "Unique Zebra Title" });
    const res = await request(app).get("/api/videos?q=zebra");
    expect(res.body.videos.length).toBe(1);
    expect(res.body.videos[0].title).toBe("Unique Zebra Title");
  });
  test("viewing increments the view count", async () => {
    const up = await upload({ title: "Viewed" });
    const id = up.body.video.id;
    await request(app).get(`/api/videos/${id}`);
    const again = await request(app).get(`/api/videos/${id}`);
    expect(again.body.video.views).toBeGreaterThanOrEqual(2);
  });
});

describe("moderation: word denylist + retention", () => {
  test("blocked term in title is rejected", async () => {
    const res = await upload({ title: "underage stuff" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/blocked term/i);
  });
  test("invalid retention falls back to default (24h)", async () => {
    const res = await upload({ title: "Ret", retentionHours: 999 });
    const ttl = res.body.video.expiresAt - Date.now();
    expect(ttl).toBeGreaterThan(23 * 3600 * 1000);
    expect(ttl).toBeLessThan(25 * 3600 * 1000);
  });
});

describe("reporting -> auto-takedown", () => {
  test("3 distinct reporters removes the video", async () => {
    const up = await upload({ title: "Reportme" });
    const id = up.body.video.id;
    for (const ip of ["9.9.9.1", "9.9.9.2"]) {
      const r = await request(app).post(`/api/videos/${id}/report`).set("X-Forwarded-For", ip).send({ reason: "bad" });
      expect(r.body.removed).toBe(false);
    }
    const final = await request(app).post(`/api/videos/${id}/report`).set("X-Forwarded-For", "9.9.9.3").send({ reason: "bad" });
    expect(final.body.removed).toBe(true);
    expect((await request(app).get(`/api/videos/${id}`)).status).toBe(404);
  });
  test("same reporter counts once", async () => {
    const up = await upload({ title: "Dedup" });
    const id = up.body.video.id;
    await request(app).post(`/api/videos/${id}/report`).set("X-Forwarded-For", "8.8.8.8").send({ reason: "x" });
    const second = await request(app).post(`/api/videos/${id}/report`).set("X-Forwarded-For", "8.8.8.8").send({ reason: "x" });
    expect(second.body.reportCount).toBe(1);
  });
});

describe("deletion", () => {
  test("wrong token is rejected, right token deletes", async () => {
    const up = await upload({ title: "Deleteme" });
    const id = up.body.video.id;
    const bad = await request(app).delete(`/api/videos/${id}`).send({ token: "nope" });
    expect(bad.status).toBe(403);
    const good = await request(app).delete(`/api/videos/${id}`).send({ token: up.body.deleteToken });
    expect(good.body.removed).toBe(true);
  });
});

describe("admin API", () => {
  test("requires the key", async () => {
    expect((await request(app).get("/api/admin/videos")).status).toBe(403);
  });
  test("lists videos with the key", async () => {
    const res = await request(app).get("/api/admin/videos").set("x-admin-key", "test-admin-key");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.videos)).toBe(true);
  });
  test("ban survives an IP change (fingerprint ban)", async () => {
    const up = await upload({ ip: "5.5.5.1", fp: "banme-fp", title: "Banned soon" });
    const id = up.body.video.id;
    const del = await request(app).delete(`/api/admin/videos/${id}?ban=1`).set("x-admin-key", "test-admin-key");
    expect(del.body.banned).toBe(true);
    // Different IP, same fingerprint → still blocked.
    const blocked = await upload({ ip: "5.5.5.99", fp: "banme-fp", title: "Try again" });
    expect(blocked.status).toBe(403);
  });
  test("blocklist rejects that exact file hash on re-upload", async () => {
    const hash = crypto.createHash("sha256").update(FAKE_MP4).digest("hex");
    await request(app).post("/api/admin/blocklist").set("x-admin-key", "test-admin-key").send({ hash });
    const res = await upload({ fp: "fresh-fp", title: "Should be blocked" });
    expect(res.status).toBe(403);
  });
});

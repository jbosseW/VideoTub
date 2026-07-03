let ADMIN_KEY = "";

const loginPanel = document.getElementById("login-panel");
const queuePanel = document.getElementById("queue-panel");
const listEl = document.getElementById("admin-list");
const countEl = document.getElementById("count");
const loginStatus = document.getElementById("login-status");

function esc(s) {
  return String(s == null ? "" : s)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}
function fmtBytes(b) {
  if (!b) return "0 B";
  const u = ["B", "KB", "MB", "GB"]; let v = b, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}
function fmtDate(t) { return new Date(t).toLocaleString(); }

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { "x-admin-key": ADMIN_KEY, ...(opts.headers || {}) },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

async function load() {
  const data = await api("/api/admin/videos");
  countEl.textContent = `(${data.videos.length})`;
  if (data.videos.length === 0) { listEl.innerHTML = "<p class='hint'>No videos.</p>"; return; }
  listEl.innerHTML = data.videos.map(renderCard).join("");
  wireCards();
}

function renderCard(v) {
  const reports = (v.reports || []).map((r) => `<li>${esc(r.reason)} <span class="hint">(${fmtDate(r.ts)})</span></li>`).join("");
  const pending = !v.approved ? `<span class="badge-pending">PENDING</span>` : "";
  const flagged = v.reportCount > 0 ? `<span class="badge-report">${v.reportCount} report(s)</span>` : "";
  return `<article class="admin-card" data-id="${esc(v.id)}">
    <div class="admin-thumb">${v.thumbUrl ? `<img src="${esc(v.thumbUrl)}" alt="">` : `<div class="noThumb">no thumb</div>`}</div>
    <div class="admin-body">
      <h3>${esc(v.title)} ${pending} ${flagged}</h3>
      <p class="hint">${fmtBytes(v.sizeBytes)} · ${v.views || 0} views · up ${fmtDate(v.uploadedAt)} · exp ${fmtDate(v.expiresAt)}</p>
      <p class="hint">uploader ip:${esc(v.uploaderIpHash || "?")} fp:${esc(v.uploaderFpHash || "-")}</p>
      ${reports ? `<details><summary>Reports</summary><ul>${reports}</ul></details>` : ""}
      <div class="actions">
        <a class="link" href="/watch.html?id=${encodeURIComponent(v.id)}" target="_blank">Watch</a>
        ${!v.approved ? `<button data-act="approve">Approve</button>` : ""}
        <button data-act="remove">Remove</button>
        <button data-act="removeblock">Remove + Block hash</button>
        <button data-act="removeban" class="danger">Remove + Ban uploader</button>
      </div>
    </div>
  </article>`;
}

function wireCards() {
  listEl.querySelectorAll(".admin-card").forEach((card) => {
    const id = card.getAttribute("data-id");
    card.querySelectorAll("button[data-act]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const act = btn.getAttribute("data-act");
        try {
          if (act === "approve") { await api(`/api/admin/videos/${encodeURIComponent(id)}/approve`, { method: "POST" }); }
          else if (act === "remove") { await api(`/api/admin/videos/${encodeURIComponent(id)}`, { method: "DELETE" }); }
          else if (act === "removeblock") { await api(`/api/admin/videos/${encodeURIComponent(id)}?block=1`, { method: "DELETE" }); }
          else if (act === "removeban") {
            if (!confirm("Remove this video, block its hash, and ban the uploader?")) return;
            await api(`/api/admin/videos/${encodeURIComponent(id)}?block=1&ban=1`, { method: "DELETE" });
          }
          await load();
        } catch (e) { alert(e.message); }
      });
    });
  });
}

document.getElementById("key-btn").addEventListener("click", async () => {
  ADMIN_KEY = document.getElementById("key-input").value.trim();
  if (!ADMIN_KEY) { loginStatus.textContent = "Enter a key."; return; }
  loginStatus.textContent = "Loading...";
  try {
    await load();
    loginPanel.style.display = "none";
    queuePanel.style.display = "";
  } catch (e) {
    loginStatus.textContent = e.message;
  }
});
document.getElementById("refresh-btn").addEventListener("click", () => load().catch((e) => alert(e.message)));

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(value >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatDate(ts) {
  return new Date(ts).toLocaleString();
}

let appConfig = {
  maxUploadMb: 250,
  allowedExtensions: [".mp4", ".webm", ".mkv", ".mov", ".avi", ".m4v"],
  retentionHours: 24,
};

const form = document.getElementById("upload-form");
const uploadBtn = document.getElementById("upload-btn");
const statusEl = document.getElementById("upload-status");
const listEl = document.getElementById("video-list");
const rulesEl = document.getElementById("upload-rules");
const videoInput = form.querySelector("input[name='video']");

function setStatus(text, isError = false) {
  statusEl.textContent = text;
  statusEl.style.color = isError ? "#ff9b9b" : "#b8fcb8";
}

function renderVideos(videos) {
  if (!Array.isArray(videos) || videos.length === 0) {
    listEl.innerHTML = "<p class='hint'>No videos uploaded yet.</p>";
    return;
  }

  listEl.innerHTML = videos
    .map((v) => {
      const title = v.title || "Untitled";
      return `<article class="card">
        <h3>${escapeHtml(title)}</h3>
        <p>Size: ${formatBytes(v.sizeBytes)} | Uploaded: ${formatDate(v.uploadedAt)}</p>
        <p>Expires: ${formatDate(v.expiresAt)}</p>
        <a href="/watch.html?id=${encodeURIComponent(v.id)}">Watch</a>
      </article>`;
    })
    .join("");
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function loadConfig() {
  const res = await fetch("/api/config");
  if (!res.ok) throw new Error("Failed to load configuration.");
  appConfig = await res.json();
  rulesEl.textContent = `Allowed: ${appConfig.allowedExtensions.join(", ")}. Max size: ${
    appConfig.maxUploadMb
  } MB. Videos auto-delete after ${appConfig.retentionHours} hours.`;
}

async function loadVideos() {
  const res = await fetch("/api/videos");
  if (!res.ok) throw new Error("Failed to load videos.");
  const payload = await res.json();
  renderVideos(payload.videos || []);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus("");

  const file = videoInput.files?.[0];
  if (!file) {
    setStatus("Pick a video file first.", true);
    return;
  }

  const maxBytes = appConfig.maxUploadMb * 1024 * 1024;
  if (file.size > maxBytes) {
    setStatus(`File too large. Max allowed size is ${appConfig.maxUploadMb} MB.`, true);
    return;
  }

  uploadBtn.disabled = true;
  setStatus("Uploading...");

  try {
    const formData = new FormData(form);
    const res = await fetch("/api/upload", {
      method: "POST",
      body: formData,
    });
    const payload = await res.json();
    if (!res.ok) {
      throw new Error(payload.error || "Upload failed.");
    }

    form.reset();
    setStatus("Upload complete.");
    await loadVideos();
  } catch (err) {
    setStatus(err.message || "Upload failed.", true);
  } finally {
    uploadBtn.disabled = false;
  }
});

async function init() {
  try {
    await loadConfig();
    await loadVideos();
  } catch (err) {
    setStatus(err.message || "Failed to initialize app.", true);
  }
}

init();

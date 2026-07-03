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

// ---- Proof-of-work solver (anti-bot). Runs SHA-256 puzzle in a Web Worker. ----
const _powWorkerCode = `
self.onmessage = async function(e) {
  var challenge = e.data.challenge, difficulty = e.data.difficulty;
  var enc = new TextEncoder(), nonce = 0, BATCH = 2048;
  function hasZeros(buf, bits) {
    var fb = Math.floor(bits/8), rb = bits%8;
    for (var i=0;i<fb;i++){ if (buf[i]!==0) return false; }
    if (rb>0){ var m = 0xFF << (8-rb); if ((buf[fb]&m)!==0) return false; }
    return true;
  }
  while (true) {
    var proms = [], base = nonce;
    for (var i=0;i<BATCH;i++){
      var n = (base+i).toString(16);
      proms.push(crypto.subtle.digest('SHA-256', enc.encode(challenge+n)).then(function(b){
        return { nonce: this, hash: new Uint8Array(b) };
      }.bind(n)));
    }
    nonce += BATCH;
    var results = await Promise.all(proms);
    for (var j=0;j<results.length;j++){
      if (hasZeros(results[j].hash, difficulty)){ self.postMessage({done:true, nonce:results[j].nonce}); return; }
    }
  }
};
`;

function solvePoW(challenge, difficulty) {
  return new Promise((resolve, reject) => {
    try {
      const url = URL.createObjectURL(new Blob([_powWorkerCode], { type: "application/javascript" }));
      const worker = new Worker(url);
      const to = setTimeout(() => { worker.terminate(); URL.revokeObjectURL(url); reject(new Error("PoW timed out")); }, 120000);
      worker.onmessage = (e) => {
        if (e.data.done) { clearTimeout(to); worker.terminate(); URL.revokeObjectURL(url); resolve(e.data.nonce); }
      };
      worker.onerror = (err) => { clearTimeout(to); worker.terminate(); URL.revokeObjectURL(url); reject(err); };
      worker.postMessage({ challenge, difficulty });
    } catch (err) { reject(err); }
  });
}

async function fetchAndSolvePoW() {
  const resp = await fetch("/api/pow/challenge");
  if (!resp.ok) throw new Error("Failed to get proof-of-work challenge.");
  const data = await resp.json();
  const nonce = await solvePoW(data.challenge, data.difficulty);
  return { challenge: data.challenge, nonce };
}

// Best-effort browser fingerprint (IP-independent abuse signal). Not a MAC
// address — a web page cannot read one — and it is defeatable, but it makes
// ban evasion by IP-change harder. Combines stable-ish signals + a canvas hash.
function computeFingerprint() {
  try {
    const parts = [
      navigator.userAgent || "",
      navigator.language || "",
      (navigator.languages || []).join(","),
      new Date().getTimezoneOffset(),
      screen.width + "x" + screen.height + "x" + (screen.colorDepth || ""),
      navigator.hardwareConcurrency || "",
      navigator.platform || "",
      navigator.deviceMemory || "",
    ];
    // Canvas fingerprint
    try {
      const c = document.createElement("canvas");
      const ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillStyle = "#f60";
      ctx.fillRect(10, 10, 60, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("VideoTub", 12, 12);
      parts.push(c.toDataURL().slice(-64));
    } catch (_) {}
    return parts.join("|");
  } catch (_) {
    return "";
  }
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

  try {
    const formData = new FormData(form);
    formData.append("fp", computeFingerprint());

    // Solve the anti-bot proof-of-work before uploading (if the server requires it).
    if (appConfig.powRequired) {
      setStatus("Verifying (proof-of-work)...");
      try {
        const pow = await fetchAndSolvePoW();
        formData.append("powChallenge", pow.challenge);
        formData.append("powNonce", pow.nonce);
      } catch (powErr) {
        throw new Error("Proof-of-work failed: " + (powErr.message || "try again"));
      }
    }

    setStatus("Uploading...");
    const res = await fetch("/api/upload", {
      method: "POST",
      body: formData,
    });
    const payload = await res.json();
    if (!res.ok) {
      throw new Error(payload.error || "Upload failed.");
    }

    // Save the delete token in this browser so the uploader can remove their
    // own video from its watch page. It is shown once and never stored server-side
    // in plaintext.
    try {
      const mine = JSON.parse(localStorage.getItem("videotub_uploads") || "[]");
      mine.push({ id: payload.video.id, token: payload.deleteToken, title: payload.video.title, ts: Date.now() });
      localStorage.setItem("videotub_uploads", JSON.stringify(mine.slice(-50)));
    } catch (_) {}

    form.reset();
    const base = payload.pending
      ? "Uploaded — held for review; it will appear once approved."
      : "Upload complete.";
    setStatus(
      payload.deleteToken
        ? `${base} Delete key (save to remove your video): ${payload.deleteToken}`
        : base
    );
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

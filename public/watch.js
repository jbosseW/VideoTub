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

function readVideoId() {
  const params = new URLSearchParams(window.location.search);
  return params.get("id");
}

async function initWatchPage() {
  const titleEl = document.getElementById("video-title");
  const metaEl = document.getElementById("video-meta");
  const descriptionEl = document.getElementById("video-description");
  const player = document.getElementById("player");
  const id = readVideoId();

  if (!id) {
    titleEl.textContent = "Video ID missing.";
    return;
  }

  try {
    const res = await fetch(`/api/videos/${encodeURIComponent(id)}`);
    const payload = await res.json();
    if (!res.ok) {
      throw new Error(payload.error || "Video not found.");
    }

    const video = payload.video;
    titleEl.textContent = video.title || "Untitled";
    metaEl.textContent = `${formatBytes(video.sizeBytes)} · ${video.views || 0} views · uploaded ${formatDate(
      video.uploadedAt
    )} · expires ${formatDate(video.expiresAt)}`;
    descriptionEl.textContent = video.description || "";
    if (video.thumbUrl) player.poster = video.thumbUrl;
    player.src = video.videoUrl;

    // Tags + embed link
    const tagsEl = document.getElementById("video-tags");
    if (tagsEl) tagsEl.innerHTML = (video.tags || []).map((t) =>
      `<a class="tag" href="/?tag=${encodeURIComponent(t)}">${t.replace(/[<>&"']/g, "")}</a>`).join("");
    const embedEl = document.getElementById("embed-code");
    if (embedEl) {
      const url = `${location.origin}/embed/${encodeURIComponent(id)}`;
      embedEl.value = `<iframe src="${url}" width="640" height="360" frameborder="0" allowfullscreen></iframe>`;
    }
    wireActions(id);
  } catch (err) {
    titleEl.textContent = err.message || "Failed to load video.";
    metaEl.textContent = "";
    descriptionEl.textContent = "";
  }
}

function localDeleteToken(id) {
  try {
    const mine = JSON.parse(localStorage.getItem("videotub_uploads") || "[]");
    const hit = mine.find((m) => m.id === id);
    return hit ? hit.token : null;
  } catch (_) {
    return null;
  }
}

function wireActions(id) {
  const statusEl = document.getElementById("action-status");
  const reportBtn = document.getElementById("report-btn");
  const deleteBtn = document.getElementById("delete-btn");
  const setMsg = (t) => { if (statusEl) statusEl.textContent = t; };

  if (reportBtn) {
    reportBtn.addEventListener("click", async () => {
      const reason = window.prompt("Why are you reporting this video? (e.g. illegal, abusive, copyright)");
      if (reason === null) return;
      reportBtn.disabled = true;
      setMsg("Submitting report...");
      try {
        const res = await fetch(`/api/videos/${encodeURIComponent(id)}/report`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reason }),
        });
        const p = await res.json();
        if (!res.ok) throw new Error(p.error || "Report failed.");
        if (p.removed) {
          setMsg("Reported. This video has been removed. Returning home...");
          setTimeout(() => (window.location.href = "/"), 1500);
        } else {
          setMsg("Thanks — your report was recorded.");
        }
      } catch (err) {
        setMsg(err.message || "Report failed.");
        reportBtn.disabled = false;
      }
    });
  }

  const myToken = localDeleteToken(id);
  if (deleteBtn && myToken) {
    deleteBtn.style.display = "";
    deleteBtn.addEventListener("click", async () => {
      if (!window.confirm("Delete this video permanently?")) return;
      deleteBtn.disabled = true;
      setMsg("Deleting...");
      try {
        const res = await fetch(`/api/videos/${encodeURIComponent(id)}`, {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: myToken }),
        });
        const p = await res.json();
        if (!res.ok) throw new Error(p.error || "Delete failed.");
        setMsg("Deleted. Returning home...");
        setTimeout(() => (window.location.href = "/"), 1200);
      } catch (err) {
        setMsg(err.message || "Delete failed.");
        deleteBtn.disabled = false;
      }
    });
  }
}

initWatchPage();

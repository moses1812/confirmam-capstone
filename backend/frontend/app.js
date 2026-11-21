// ==========================================
// 0. API HELPERS (talks to the ConfirmAm FastAPI backend)
// ==========================================
// Served by the backend (http://127.0.0.1:8000/) -> same origin. Opened any other way (Live Server, file) -> call the backend directly.
const API_BASE = location.port === "8000" ? "" : "http://127.0.0.1:8000";
const TOKEN_KEY = "confirmam_admin_token";

// Escape anything that came from users before putting it into innerHTML (prevents XSS).
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  const token = sessionStorage.getItem(TOKEN_KEY);
  if (token) headers["Authorization"] = "Bearer " + token;

  let res;
  try {
    res = await fetch(API_BASE + path, { ...options, headers });
  } catch (e) {
    throw new Error("Cannot reach the ConfirmAm server. Make sure the backend is running.");
  }
  if (res.status === 401 && path.startsWith("/api/v1/admin") && !path.endsWith("/login")) {
    sessionStorage.removeItem(TOKEN_KEY);
    showAdminLogin();
    throw new Error("Session expired. Please sign in again.");
  }
  if (!res.ok) {
    let msg = "Request failed (" + res.status + ")";
    try {
      const body = await res.json();
      if (typeof body.detail === "string") msg = body.detail;
      else if (Array.isArray(body.detail)) msg = "Please check your input and try again.";
    } catch (_) {}
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
}

// ==========================================
// 1. SAMPLE SCAM LOADER (index.html)
// ==========================================
function loadSampleScam() {
  const inputBox = document.getElementById("scanInput");
  if (inputBox) {
    inputBox.value =
      "URGENT: Dear Customer, your GTBank account will be blocked today. Verify your BVN and OTP immediately at http://gtb-security-update.xyz to avoid suspension.";
  }
}

// ==========================================
// 2. UNIFIED FRAUD SCANNER (index.html) -> POST /api/v1/scan
// ==========================================
async function runConfirmAm() {
  const input = document.getElementById("scanInput").value.trim();
  if (!input) {
    alert("Please paste a link, message, or phone number first!");
    return;
  }

  const btn = document.querySelector('button[onclick="runConfirmAm()"]');
  const idleText = btn ? btn.textContent : "";
  if (btn) { btn.disabled = true; btn.textContent = "Checking..."; }

  let data;
  try {
    data = await api("/api/v1/scan", { method: "POST", body: JSON.stringify({ input }) });
  } catch (err) {
    alert(err.message);
    return;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = idleText; }
  }

  const level = data.risk_level;
  const score = data.risk_score;
  const flags = [...new Set(data.signals.map((s) => s.detail))];
  const advice = data.recommendations;

  const resultBox = document.getElementById("resultBox");
  const verdictTitle = document.getElementById("verdictTitle");
  const riskScoreBadge = document.getElementById("riskScoreBadge");

  resultBox.classList.remove("hidden");
  riskScoreBadge.textContent = score + "%";
  verdictTitle.textContent = data.verdict;

  const color = level === "high" || level === "critical" ? "red" : level === "medium" ? "amber" : "emerald";
  verdictTitle.className = `text-2xl font-extrabold text-${color}-400`;
  riskScoreBadge.className = `text-3xl font-black text-${color}-400`;

  if (color === "emerald" && flags.length === 0) {
    flags.push("No common phishing keywords, suspicious domains, or blacklisted indicators detected.");
  }

  document.getElementById("flagsList").innerHTML = flags.map((f) => `<li>${esc(f)}</li>`).join("");
  document.getElementById("adviceList").innerHTML = advice.map((a) => `<li>${esc(a)}</li>`).join("");
  resultBox.scrollIntoView({ behavior: "smooth" });
}

// ==========================================
// 3. SUBMIT SCAM REPORT (report.html) -> POST /api/v1/reports
// ==========================================
async function submitScamReport(event) {
  event.preventDefault();

  const payload = {
    category: document.getElementById("scamCategory").value,
    indicator: document.getElementById("scamIndicator").value.trim(),
    details: document.getElementById("scamDetails").value.trim(),
  };

  try {
    await api("/api/v1/reports", { method: "POST", body: JSON.stringify(payload) });
  } catch (err) {
    alert(err.message);
    return;
  }

  document.getElementById("scamReportForm").reset();
  document.getElementById("reportSuccess").classList.remove("hidden");
}

// ==========================================
// 4. ADMIN DASHBOARD (admin.html)
// ==========================================
function showAdminLogin() {
  const login = document.getElementById("adminLoginBox");
  const dash = document.getElementById("adminDashboardContent");
  if (login) login.classList.remove("hidden");
  if (dash) dash.classList.add("hidden");
  const so = document.getElementById("signOutLink");
  if (so) so.classList.add("hidden");
}

function showAdminDashboard() {
  document.getElementById("adminLoginBox").classList.add("hidden");
  document.getElementById("adminDashboardContent").classList.remove("hidden");
  const so = document.getElementById("signOutLink");
  if (so) so.classList.remove("hidden");
}

async function handleAdminLogin(event) {
  event.preventDefault();
  const passcode = document.getElementById("adminPass").value;
  try {
    const data = await api("/api/v1/admin/login", { method: "POST", body: JSON.stringify({ passcode }) });
    sessionStorage.setItem(TOKEN_KEY, data.token);
    document.getElementById("adminPass").value = "";
    showAdminDashboard();
    loadAdminReports();
  } catch (err) {
    alert(err.message === "Invalid passcode" ? "Invalid passcode!" : err.message);
  }
}

let reportFilter = "Pending";

function setReportFilter(status) {
  reportFilter = status;
  loadAdminReports();
}

function adminLogout() {
  sessionStorage.removeItem(TOKEN_KEY);
  showAdminLogin();
}

async function loadPhoneListStatus() {
  const info = document.getElementById("phoneListInfo");
  if (!info) return;
  try {
    const d = await api("/api/v1/admin/phone-list");
    const when = d.last_sync ? new Date(d.last_sync).toLocaleString() : "never";
    info.textContent = d.enabled ? `${d.count} numbers, last updated: ${when}` : "Turned off (PHONE_LIST_ENABLED=false)";
  } catch (err) {
    info.textContent = err.message;
  }
}

async function syncPhoneList() {
  const btn = document.getElementById("phoneSyncBtn");
  if (btn) { btn.disabled = true; btn.textContent = "Syncing..."; }
  try {
    await api("/api/v1/admin/phone-list/sync", { method: "POST" });
  } catch (err) {
    alert(err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Sync now"; }
  }
  loadPhoneListStatus();
}

async function loadAdminReports() {
  const container = document.getElementById("reportsContainer");
  if (!container) return;

  if (!sessionStorage.getItem(TOKEN_KEY)) {
    showAdminLogin();
    return;
  }
  showAdminDashboard();
  loadPhoneListStatus();
  for (const f of ["Pending", "Verified", "Rejected", "All"]) {
    const b = document.getElementById("flt-" + f);
    if (b) b.style.outline = (f === (reportFilter || "All")) ? "2px solid #34d399" : "none";
  }

  let reports, stats;
  try {
    [reports, stats] = await Promise.all([api("/api/v1/admin/reports" + (reportFilter ? "?status=" + reportFilter : "")), api("/api/v1/admin/stats")]);
  } catch (err) {
    container.innerHTML = `<p style="color: #f87171; text-align: center; padding: 20px;">${esc(err.message)}</p>`;
    return;
  }

  document.getElementById("statTotal").textContent = stats.total;
  document.getElementById("statPending").textContent = stats.pending;
  document.getElementById("statApproved").textContent = stats.verified;

  if (reports.length === 0) {
    container.innerHTML = `<p style="color: #94a3b8; text-align: center; padding: 20px;">No reports in this view.</p>`;
    return;
  }

  container.innerHTML = reports
    .map((r) => {
      const badge = r.status === "Verified" ? "#064e3b" : r.status === "Rejected" ? "#7f1d1d" : "#78350f";
      const when = new Date(r.created_at).toLocaleDateString();
      return `
      <div class="bg-slate-950" style="margin-top: 0;">
        <div style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
          <span style="font-size: 0.8rem; color: #34d399; font-weight: 700;">${esc(r.category)}</span>
          <span style="font-size: 0.8rem; padding: 2px 10px; border-radius: 999px; background: ${badge}; color: #fff;">
            ${esc(r.status)} • ${esc(when)}
          </span>
        </div>
        <h4 style="color: #fff; margin: 6px 0; font-size: 1.05rem; word-break: break-all;">${esc(r.indicator)}</h4>
        <p style="color: #94a3b8; font-size: 0.9rem; margin-bottom: 12px;">${esc(r.details)}</p>
        <div style="display: flex; gap: 10px;">
          <button onclick="updateReportStatus(${Number(r.id)}, 'Verified')" style="background: #10b981; color: #020617; padding: 6px 14px; font-size: 0.85rem;">
            ✅ Approve & Add to Scam DB
          </button>
          <button onclick="updateReportStatus(${Number(r.id)}, 'Rejected')" style="background: #ef4444; color: #fff; padding: 6px 14px; font-size: 0.85rem;">
            ❌ Reject
          </button>
        </div>
      </div>`;
    })
    .join("");
}

async function updateReportStatus(id, newStatus) {
  try {
    await api(`/api/v1/admin/reports/${id}`, { method: "PATCH", body: JSON.stringify({ status: newStatus }) });
  } catch (err) {
    alert(err.message);
    return;
  }
  loadAdminReports();
}

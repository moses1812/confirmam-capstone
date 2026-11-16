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
// 2. UNIFIED FRAUD SCANNER (index.html)
// ==========================================
function runConfirmAm() {
  const input = document.getElementById("scanInput").value.trim();
  if (!input) {
    alert("Please paste a link, message, or phone number first!");
    return;
  }

  const lower = input.toLowerCase();
  let score = 10;
  let flags = [];
  let advice = [];

  // A. Check Verified Scam Database (approved in Admin Dashboard)
  const reports = JSON.parse(localStorage.getItem("confirmam_reports")) || [];
  const verifiedMatch = reports.find(
    (r) =>
      r.status === "Verified" &&
      (lower.includes(r.indicator.toLowerCase()) || r.indicator.toLowerCase().includes(lower))
  );

  if (verifiedMatch) {
    score = 98;
    flags.push(`CONFIRMED SCAM: Flagged in ConfirmAm Database under "${verifiedMatch.category}".`);
    flags.push(`Reported Details: ${verifiedMatch.details}`);
  }

  // B. Detect Nigerian Phone Numbers (11 digits like 08012345678 or +234...)
  const isPhone = /^(\+234|0)\d{10}$/.test(input.replace(/\s+/g, ""));
  if (isPhone && !verifiedMatch) {
    score = 35;
    flags.push("Identified as a Nigerian mobile phone number.");
    flags.push("Not currently listed in the verified scam blacklist, but exercise caution with unknown callers.");
  }

  // C. Detect Phishing, Impersonation & Fake Investment Indicators
  if (lower.includes("bvn") || lower.includes("otp") || lower.includes("pin") || lower.includes("password")) {
    score += 45;
    flags.push("Requests sensitive banking credentials (BVN, OTP, PIN, or password).");
  }
  if (lower.includes("urgent") || lower.includes("blocked") || lower.includes("suspended") || lower.includes("24 hours")) {
    score += 20;
    flags.push("Uses high-pressure urgency tactics to force panic.");
  }
  if (lower.includes(".xyz") || lower.includes(".top") || lower.includes("bit.ly") || lower.includes("http://")) {
    score += 25;
    flags.push("Contains an unverified, shortened, or insecure (non-HTTPS) link.");
  }
  if (lower.includes("double") || lower.includes("roi") || lower.includes("investment") || lower.includes("guaranteed profit")) {
    score += 35;
    flags.push("Contains Ponzi / unrealistic financial return promises.");
  }
  if (lower.includes("gtbank") || lower.includes("opay") || lower.includes("palmpay") || lower.includes("access") || lower.includes("efcc")) {
    score += 15;
    flags.push("Mentions a Nigerian financial or government institution — verify via their official app.");
  }

  if (score > 100) score = 98;

  const resultBox = document.getElementById("resultBox");
  const verdictTitle = document.getElementById("verdictTitle");
  const riskScoreBadge = document.getElementById("riskScoreBadge");
  const flagsList = document.getElementById("flagsList");
  const adviceList = document.getElementById("adviceList");

  resultBox.classList.remove("hidden");
  riskScoreBadge.textContent = score + "%";

  if (score >= 70) {
    verdictTitle.textContent = "HIGH RISK — LIKELY SCAM";
    verdictTitle.className = "text-2xl font-extrabold text-red-400";
    riskScoreBadge.className = "text-3xl font-black text-red-400";
    advice = [
      "Do NOT send money, click any link, or reply to this contact.",
      "Legitimate banks and fintechs never ask for your BVN, PIN, or OTP via SMS, call, or external link.",
      "If you already shared details or sent funds, freeze your account via your bank's USSD code and contact their fraud desk immediately."
    ];
  } else if (score >= 35) {
    verdictTitle.textContent = "MEDIUM RISK — PROCEED WITH CAUTION";
    verdictTitle.className = "text-2xl font-extrabold text-amber-400";
    riskScoreBadge.className = "text-3xl font-black text-amber-400";
    advice = [
      "Verify the person's identity through a trusted secondary channel before sending money.",
      "Avoid paying upfront fees before delivery or service verification.",
      "If they attempt to defraud you, submit their details on our 'Report a Scam' page."
    ];
  } else {
    verdictTitle.textContent = "LOW RISK — NO OBVIOUS THREATS";
    verdictTitle.className = "text-2xl font-extrabold text-emerald-400";
    riskScoreBadge.className = "text-3xl font-black text-emerald-400";
    if (flags.length === 0) {
      flags.push("No common phishing keywords, suspicious domains, or blacklisted indicators detected.");
    }
    advice = [
      "Still remain cautious before sharing personal or financial information."
    ];
  }

  flagsList.innerHTML = flags.map(f => `<li>${f}</li>`).join("");
  adviceList.innerHTML = advice.map(a => `<li>${a}</li>`).join("");
  resultBox.scrollIntoView({ behavior: "smooth" });
}

// ==========================================
// 3. SUBMIT SCAM REPORT (report.html)
// ==========================================
function submitScamReport(event) {
  event.preventDefault();

  const category = document.getElementById("scamCategory").value;
  const indicator = document.getElementById("scamIndicator").value.trim();
  const details = document.getElementById("scamDetails").value.trim();

  const newReport = {
    id: Date.now(),
    category: category,
    indicator: indicator,
    details: details,
    status: "Pending",
    date: new Date().toLocaleDateString()
  };

  const existingReports = JSON.parse(localStorage.getItem("confirmam_reports")) || [];
  existingReports.unshift(newReport);
  localStorage.setItem("confirmam_reports", JSON.stringify(existingReports));

  document.getElementById("scamReportForm").reset();
  document.getElementById("reportSuccess").classList.remove("hidden");
}

// ==========================================
// 4. ADMIN DASHBOARD (admin.html)
// ==========================================
function handleAdminLogin(event) {
  event.preventDefault();
  const pass = document.getElementById("adminPass").value;
  if (pass === "admin123") {
    document.getElementById("adminLoginBox").classList.add("hidden");
    document.getElementById("adminDashboardContent").classList.remove("hidden");
    loadAdminReports();
  } else {
    alert("Invalid passcode! Use: admin123");
  }
}

function loadAdminReports() {
  const container = document.getElementById("reportsContainer");
  if (!container) return;

  const reports = JSON.parse(localStorage.getItem("confirmam_reports")) || [];

  document.getElementById("statTotal").textContent = reports.length;
  document.getElementById("statPending").textContent = reports.filter(r => r.status === "Pending").length;
  document.getElementById("statApproved").textContent = reports.filter(r => r.status === "Verified").length;

  if (reports.length === 0) {
    container.innerHTML = `<p style="color: #94a3b8; text-align: center; padding: 20px;">No reports submitted yet. Submit one on the Report page or click "+ Load Sample Reports".</p>`;
    return;
  }

  container.innerHTML = reports
    .map(
      (r) => `
      <div class="bg-slate-950" style="margin-top: 0;">
        <div style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
          <span style="font-size: 0.8rem; color: #34d399; font-weight: 700;">${r.category}</span>
          <span style="font-size: 0.8rem; padding: 2px 10px; border-radius: 999px; background: ${
            r.status === "Verified" ? "#064e3b" : r.status === "Rejected" ? "#7f1d1d" : "#78350f"
          }; color: #fff;">
            ${r.status} • ${r.date}
          </span>
        </div>
        <h4 style="color: #fff; margin: 6px 0; font-size: 1.05rem;">${r.indicator}</h4>
        <p style="color: #94a3b8; font-size: 0.9rem; margin-bottom: 12px;">${r.details}</p>
        <div style="display: flex; gap: 10px;">
          <button onclick="updateReportStatus(${r.id}, 'Verified')" style="background: #10b981; color: #020617; padding: 6px 14px; font-size: 0.85rem;">
            ✅ Approve & Add to Scam DB
          </button>
          <button onclick="updateReportStatus(${r.id}, 'Rejected')" style="background: #ef4444; color: #fff; padding: 6px 14px; font-size: 0.85rem;">
            ❌ Reject
          </button>
        </div>
      </div>
    `
    )
    .join("");
}

function updateReportStatus(id, newStatus) {
  let reports = JSON.parse(localStorage.getItem("confirmam_reports")) || [];
  reports = reports.map((r) => (r.id === id ? { ...r, status: newStatus } : r));
  localStorage.setItem("confirmam_reports", JSON.stringify(reports));
  loadAdminReports();
}

function seedDemoReports() {
  const sampleData = [
    {
      id: 101,
      category: "Ponzi / Fake Investment Platform",
      indicator: "http://naija-wealth-double.xyz",
      details: "Promises 100% ROI in 24 hours via WhatsApp broadcast and blocks withdrawals.",
      status: "Pending",
      date: new Date().toLocaleDateString()
    },
    {
      id: 102,
      category: "Fake Bank / Fintech Impersonation",
      indicator: "08012345678 / http://opay-bvn-link.top",
      details: "SMS claiming OPay wallet is blocked and requesting 6-digit OTP.",
      status: "Verified",
      date: new Date().toLocaleDateString()
    }
  ];
  const existing = JSON.parse(localStorage.getItem("confirmam_reports")) || [];
  localStorage.setItem("confirmam_reports", JSON.stringify([...sampleData, ...existing]));
  loadAdminReports();
}
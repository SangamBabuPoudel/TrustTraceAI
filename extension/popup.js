const API_URL = "http://127.0.0.1:8000/api/analyze-page";
const MAX_VISIBLE_TEXT_LENGTH = 5000;

const RISK_MESSAGES = {
  low: "Looks safe based on current checks.",
  medium: "Some suspicious signals found.",
  high: "Strong phishing indicators detected."
};

const RISK_COLORS = {
  low: "#2dd4bf",
  medium: "#fbbf24",
  high: "#fb7185"
};

const currentUrlElement = document.getElementById("current-url");
const backendStatusElement = document.getElementById("backend-status");
const loadingStateElement = document.getElementById("loading-state");
const statusElement = document.getElementById("status");
const resultElement = document.getElementById("result");
const errorStateElement = document.getElementById("error-state");
const scoreMeterElement = document.getElementById("score-meter");
const riskLevelElement = document.getElementById("risk-level");
const riskMessageElement = document.getElementById("risk-message");
const trustScoreElement = document.getElementById("trust-score");
const phishingProbabilityElement = document.getElementById("phishing-probability");
const probabilityBarElement = document.getElementById("probability-bar");
const reasonsElement = document.getElementById("reasons");
const rescanButton = document.getElementById("rescan");
const copyUrlButton = document.getElementById("copy-url");
const copyReportButton = document.getElementById("copy-report");

let currentTabUrl = "";
let latestResult = null;

async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function collectPageContent(tab) {
  if (!tab?.id) {
    return {
      page_title: tab?.title || "",
      visible_text: "",
      forms: []
    };
  }

  try {
    const pageContent = await chrome.tabs.sendMessage(tab.id, {
      type: "TRUSTTRACE_COLLECT_PAGE"
    });

    return {
      page_title: pageContent?.pageTitle || tab?.title || "",
      visible_text: (pageContent?.visibleText || "").slice(0, MAX_VISIBLE_TEXT_LENGTH),
      forms: pageContent?.forms || []
    };
  } catch (error) {
    return {
      page_title: tab?.title || "",
      visible_text: "",
      forms: []
    };
  }
}

async function analyzePage(payload) {
  const response = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error("The local TrustTrace API returned an error.");
  }

  return response.json();
}

function setBackendStatus(status) {
  backendStatusElement.className = `status-pill ${status}`;
  backendStatusElement.innerHTML = `<span class="status-dot"></span>${status === "online" ? "Online" : status === "offline" ? "Offline" : "Checking"}`;
}

function showLoading() {
  setBackendStatus("checking");
  latestResult = null;
  copyReportButton.disabled = true;
  errorStateElement.hidden = true;
  resultElement.hidden = true;
  loadingStateElement.hidden = false;
  statusElement.textContent = "Analyzing URL and page content signals...";
}

function showError(title, message, backendStatus = "offline") {
  setBackendStatus(backendStatus);
  loadingStateElement.hidden = true;
  resultElement.hidden = true;
  errorStateElement.hidden = false;
  errorStateElement.querySelector("strong").textContent = title;
  errorStateElement.querySelector("p").textContent = message;
}

function getRiskLabel(riskLevel) {
  if (riskLevel === "high") {
    return "High Risk";
  }
  if (riskLevel === "medium") {
    return "Medium Risk";
  }
  return "Low Risk";
}

function animateTrustScore(score, riskLevel) {
  const duration = 800;
  const startTime = performance.now();
  const color = RISK_COLORS[riskLevel] || RISK_COLORS.low;

  scoreMeterElement.style.setProperty("--risk-color", color);

  function step(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const easedProgress = 1 - Math.pow(1 - progress, 3);
    const currentScore = Math.round(score * easedProgress);

    trustScoreElement.textContent = currentScore;
    scoreMeterElement.style.setProperty("--score-percent", `${currentScore}%`);

    if (progress < 1) {
      requestAnimationFrame(step);
    }
  }

  requestAnimationFrame(step);
}

function createReasonCard(reason, riskLevel, index) {
  const reasonCard = document.createElement("div");
  reasonCard.className = `reason-card ${riskLevel}`;
  reasonCard.style.animationDelay = `${index * 45}ms`;

  const icon = document.createElement("span");
  icon.className = "reason-icon";
  icon.textContent = riskLevel === "low" ? "OK" : "!";

  const text = document.createElement("span");
  text.textContent = reason;

  reasonCard.append(icon, text);
  return reasonCard;
}

function createReasonGroup(title, reasons, riskLevel, startIndex) {
  const group = document.createElement("div");
  group.className = "reason-group";

  const heading = document.createElement("span");
  heading.className = "reason-group-title";
  heading.textContent = title;
  group.appendChild(heading);

  reasons.forEach((reason, index) => {
    group.appendChild(createReasonCard(reason, riskLevel, startIndex + index));
  });

  return group;
}

function renderReasons(result, riskLevel) {
  reasonsElement.innerHTML = "";

  const safeReason =
    "No obvious phishing indicators were found by the MVP checks.";
  const urlSignals = result.signals?.url_signals || [];
  const contentSignals = result.signals?.content_signals || [];
  const formSignals = result.signals?.form_signals || [];
  const hasGroupedSignals =
    urlSignals.length > 0 || contentSignals.length > 0 || formSignals.length > 0;

  if (hasGroupedSignals) {
    let animationIndex = 0;

    if (urlSignals.length > 0) {
      reasonsElement.appendChild(
        createReasonGroup("URL signals", urlSignals, riskLevel, animationIndex)
      );
      animationIndex += urlSignals.length;
    }

    if (contentSignals.length > 0) {
      reasonsElement.appendChild(
        createReasonGroup("Page content signals", contentSignals, riskLevel, animationIndex)
      );
      animationIndex += contentSignals.length;
    }

    if (formSignals.length > 0) {
      reasonsElement.appendChild(
        createReasonGroup("Form signals", formSignals, riskLevel, animationIndex)
      );
    }

    return;
  }

  const reasons = result.reasons || [];
  const normalizedReasons =
    reasons.length === 1 && reasons[0].includes("No obvious phishing indicators")
      ? [safeReason]
      : reasons;

  normalizedReasons.forEach((reason, index) => {
    reasonsElement.appendChild(createReasonCard(reason, riskLevel, index));
  });
}

function renderResult(result) {
  const riskLevel = result.risk_level || "low";
  const trustScore = Number(result.trust_score) || 0;
  const phishingPercent = Math.round((Number(result.phishing_probability) || 0) * 100);

  latestResult = result;
  setBackendStatus("online");
  loadingStateElement.hidden = true;
  errorStateElement.hidden = true;
  resultElement.hidden = false;
  copyReportButton.disabled = false;

  riskLevelElement.textContent = getRiskLabel(riskLevel);
  riskLevelElement.className = `risk-badge ${riskLevel}`;
  riskMessageElement.textContent = RISK_MESSAGES[riskLevel] || RISK_MESSAGES.low;

  phishingProbabilityElement.textContent = `${phishingPercent}%`;
  probabilityBarElement.className = `progress-fill ${riskLevel}`;
  probabilityBarElement.style.width = "0%";

  requestAnimationFrame(() => {
    probabilityBarElement.style.width = `${phishingPercent}%`;
  });

  animateTrustScore(trustScore, riskLevel);
  renderReasons(result, riskLevel);
}

async function scanCurrentUrl() {
  showLoading();

  try {
    const tab = await getCurrentTab();
    currentTabUrl = tab?.url || "";
    currentUrlElement.textContent = currentTabUrl || "No supported URL found.";
    currentUrlElement.title = currentTabUrl;

    if (!currentTabUrl.startsWith("http://") && !currentTabUrl.startsWith("https://")) {
      showError(
        "Unsupported page",
        "Open an HTTP or HTTPS page to analyze it.",
        "checking"
      );
      return;
    }

    const pageContent = await collectPageContent(tab);
    const result = await analyzePage({
      url: currentTabUrl,
      page_title: pageContent.page_title,
      visible_text: pageContent.visible_text,
      forms: pageContent.forms
    });
    renderResult(result);
  } catch (error) {
    showError(
      "Backend unavailable",
      "Backend unavailable. Start the FastAPI server and try again."
    );
  }
}

async function copyText(text, button, successLabel) {
  if (!text) {
    return;
  }

  const originalLabel = button.textContent;
  await navigator.clipboard.writeText(text);
  button.textContent = successLabel;

  setTimeout(() => {
    button.textContent = originalLabel;
  }, 1400);
}

function buildReport() {
  const reasons = latestResult?.reasons?.length
    ? latestResult.reasons.join("\n- ")
    : "None";
  const urlSignals = latestResult?.signals?.url_signals?.length
    ? latestResult.signals.url_signals.join("\n- ")
    : "None";
  const contentSignals = latestResult?.signals?.content_signals?.length
    ? latestResult.signals.content_signals.join("\n- ")
    : "None";
  const formSignals = latestResult?.signals?.form_signals?.length
    ? latestResult.signals.form_signals.join("\n- ")
    : "None";

  return `TrustTrace AI Scan Report
URL: ${latestResult?.url || currentTabUrl}
Risk Level: ${latestResult?.risk_level || "Unavailable"}
Trust Score: ${latestResult?.trust_score ?? "Unavailable"}
Phishing Probability: ${Math.round((latestResult?.phishing_probability || 0) * 100)}%
Reasons:
- ${reasons}
URL Signals:
- ${urlSignals}
Page Content Signals:
- ${contentSignals}
Form Signals:
- ${formSignals}`;
}

rescanButton.addEventListener("click", scanCurrentUrl);

copyUrlButton.addEventListener("click", async () => {
  try {
    await copyText(currentTabUrl, copyUrlButton, "Copied");
  } catch (error) {
    copyUrlButton.textContent = "Failed";
  }
});

copyReportButton.addEventListener("click", async () => {
  if (!latestResult) {
    return;
  }

  try {
    await copyText(buildReport(), copyReportButton, "Report Copied");
  } catch (error) {
    copyReportButton.textContent = "Copy Failed";
  }
});

scanCurrentUrl();

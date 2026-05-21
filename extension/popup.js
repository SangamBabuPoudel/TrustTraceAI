const API_URL = "http://127.0.0.1:8000/api/analyze-url";

const currentUrlElement = document.getElementById("current-url");
const statusElement = document.getElementById("status");
const resultElement = document.getElementById("result");
const riskLevelElement = document.getElementById("risk-level");
const trustScoreElement = document.getElementById("trust-score");
const phishingProbabilityElement = document.getElementById("phishing-probability");
const reasonsElement = document.getElementById("reasons");

async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function analyzeUrl(url) {
  const response = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url })
  });

  if (!response.ok) {
    throw new Error("The local TrustTrace API returned an error.");
  }

  return response.json();
}

function renderResult(result) {
  riskLevelElement.textContent = result.risk_level;
  riskLevelElement.className = `risk ${result.risk_level}`;
  trustScoreElement.textContent = result.trust_score;
  phishingProbabilityElement.textContent = `${Math.round(
    result.phishing_probability * 100
  )}%`;

  reasonsElement.innerHTML = "";
  result.reasons.forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasonsElement.appendChild(item);
  });

  resultElement.hidden = false;
  statusElement.textContent = "Analysis complete.";
}

async function initPopup() {
  try {
    const tab = await getCurrentTab();
    const tabUrl = tab?.url || "";

    if (!tabUrl.startsWith("http://") && !tabUrl.startsWith("https://")) {
      currentUrlElement.textContent = tabUrl || "No supported URL found.";
      statusElement.textContent = "Open an HTTP or HTTPS page to analyze it.";
      return;
    }

    currentUrlElement.textContent = tabUrl;
    const result = await analyzeUrl(tabUrl);
    renderResult(result);
  } catch (error) {
    statusElement.textContent =
      "Could not analyze this URL. Make sure the FastAPI backend is running locally.";
  }
}

initPopup();

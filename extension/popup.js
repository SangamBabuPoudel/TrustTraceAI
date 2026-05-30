const PAGE_API_URL = "http://127.0.0.1:8000/api/analyze-page";
const MESSAGE_API_URL = "http://127.0.0.1:8000/api/analyze-message";
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
const repeatNoteElement = document.getElementById("repeat-note");
const rescanButton = document.getElementById("rescan");
const copyUrlButton = document.getElementById("copy-url");
const copyReportButton = document.getElementById("copy-report");
const scanMessageButton = document.getElementById("scan-message");
const senderInputElement = document.getElementById("sender-input");
const messagePreviewElement = document.getElementById("message-preview");
const nearbyThreatsElement = document.getElementById("nearby-threats");

let currentTabUrl = "";
let latestResult = null;
let latestScanType = "website";
let messageCandidates = [];
let selectedMessageCandidateId = null;

async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function collectPageContent(tab) {
  if (!tab?.id) {
    return {
      page_title: tab?.title || "",
      selected_text: "",
      visible_text: "",
      forms: [],
      links: [],
      message_candidates: []
    };
  }

  try {
    const pageContent = await chrome.tabs.sendMessage(tab.id, {
      type: "TRUSTTRACE_COLLECT_PAGE"
    });

    return normalizePageContent(pageContent, tab);
  } catch (error) {
    return collectPageContentWithScripting(tab);
  }
}

async function collectPageContentWithScripting(tab) {
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: collectTrustTracePageSnapshot,
      args: [MAX_VISIBLE_TEXT_LENGTH]
    });

    return normalizePageContent(result?.result, tab);
  } catch (error) {
    return {
      page_title: tab?.title || "",
      selected_text: "",
      visible_text: "",
      forms: [],
      links: [],
      message_candidates: []
    };
  }
}

function normalizePageContent(pageContent, tab) {
  return {
    page_title: pageContent?.pageTitle || tab?.title || "",
    selected_text: (pageContent?.selectedText || "").slice(0, MAX_VISIBLE_TEXT_LENGTH),
    visible_text: (pageContent?.visibleText || "").slice(0, MAX_VISIBLE_TEXT_LENGTH),
    forms: pageContent?.forms || [],
    links: pageContent?.links || [],
    message_candidates: pageContent?.messageCandidates || []
  };
}

function collectTrustTracePageSnapshot(maxVisibleTextLength) {
  function getVisibleBodyText() {
    const bodyText = document.body?.innerText || "";
    return bodyText.replace(/\s+/g, " ").trim();
  }

  function getSelectedText() {
    return window.getSelection()?.toString().replace(/\s+/g, " ").trim() || "";
  }

  function isEmailOrUsernameInput(input) {
    const inputType = input.type.toLowerCase();
    const inputName = `${input.name || ""} ${input.id || ""} ${input.placeholder || ""}`.toLowerCase();

    return (
      inputType === "email" ||
      inputName.includes("email") ||
      inputName.includes("user") ||
      inputName.includes("login")
    );
  }

  function getSubmitText(submitButton) {
    if (!submitButton) {
      return "";
    }

    if (submitButton.tagName.toLowerCase() === "input") {
      return submitButton.value || "";
    }

    return submitButton.innerText || submitButton.textContent || "";
  }

  function collectFormMetadata() {
    return Array.from(document.forms).map((form) => {
      const inputs = Array.from(form.querySelectorAll("input"));
      const submitButton = form.querySelector(
        "button[type='submit'], input[type='submit'], button:not([type])"
      );

      return {
        action: form.getAttribute("action") || "",
        method: (form.getAttribute("method") || "get").toLowerCase(),
        has_password_field: inputs.some((input) => input.type === "password"),
        has_email_or_username_field: inputs.some(isEmailOrUsernameInput),
        input_count: inputs.length,
        hidden_input_count: inputs.filter((input) => input.type === "hidden").length,
        submit_text: getSubmitText(submitButton)
      };
    });
  }

  function collectVisibleLinks() {
    return Array.from(document.querySelectorAll("a[href]"))
      .filter((link) => link.innerText.trim() || link.href)
      .slice(0, 30)
      .map((link) => ({
        text: link.innerText.replace(/\s+/g, " ").trim(),
        href: link.href
      }));
  }

  function getCandidateElements() {
    const selectors = [
      ".trusttrace-message-card",
      "[data-trusttrace-message]",
      "[data-sender]",
      "[data-subject]",
      "article",
      "[role='article']",
      ".message",
      ".email",
      ".mail",
      ".conversation",
      ".chat-message"
    ];

    return Array.from(document.querySelectorAll(selectors.join(",")))
      .filter((element, index, elements) => {
        const rect = element.getBoundingClientRect();
        const style = window.getComputedStyle(element);
        return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden" && !elements.some((other, otherIndex) => otherIndex < index && other.contains(element));
      });
  }

  function extractSender(element, text) {
    const explicitSender = element.getAttribute("data-sender");
    if (explicitSender) return explicitSender.trim();
    const match = text.match(/\b(?:sender|from):\s*([^\n]+?)(?:\s{2,}| subject:| message:|$)/i);
    return match ? match[1].trim() : "";
  }

  function extractSubject(element, text) {
    const explicitSubject = element.getAttribute("data-subject");
    if (explicitSubject) return explicitSubject.trim();
    const heading = element.querySelector("h1, h2, h3, [data-subject]");
    if (heading?.innerText) return heading.innerText.trim();
    const match = text.match(/\bsubject:\s*([^\n]+?)(?:\s{2,}| sender:| from:| message:|$)/i);
    return match ? match[1].trim() : document.title || "";
  }

  function collectMessageCandidates() {
    const selectedText = getSelectedText();
    return getCandidateElements()
      .map((element, index) => {
        const rect = element.getBoundingClientRect();
        const messageText = (element.innerText || "").replace(/\s+/g, " ").trim();
        const links = Array.from(element.querySelectorAll("a[href]")).map((link) => ({
          text: link.innerText.replace(/\s+/g, " ").trim(),
          href: link.href
        }));
        const sender = extractSender(element, messageText);
        const subject = extractSubject(element, messageText);
        let confidenceScore = 0;
        if (element.matches(".trusttrace-message-card, [data-trusttrace-message]")) confidenceScore += 50;
        if (element.matches("[data-sender], [data-subject], article, [role='article']")) confidenceScore += 25;
        if (sender) confidenceScore += 15;
        if (subject) confidenceScore += 10;
        if (links.length > 0) confidenceScore += 10;
        if (/(urgent|suspended|locked|verify|password|security code|payment failed)/i.test(messageText)) confidenceScore += 20;
        if (selectedText && messageText.includes(selectedText)) confidenceScore += 50;

        return {
          candidate_id: `message-${index + 1}`,
          sender,
          subject,
          preview: messageText.slice(0, 300),
          message_text: messageText.slice(0, maxVisibleTextLength),
          links,
          source_url: window.location.href,
          confidence_score: confidenceScore,
          contains_selection: Boolean(selectedText && messageText.includes(selectedText)),
          position: {
            top: Math.max(0, Math.round(rect.top + window.scrollY)),
            left: Math.max(0, Math.round(rect.left + window.scrollX)),
            width: Math.round(rect.width),
            height: Math.round(rect.height)
          }
        };
      })
      .filter((candidate) => candidate.message_text.length >= 20)
      .sort((a, b) => b.confidence_score - a.confidence_score || a.position.top - b.position.top)
      .slice(0, 12);
  }

  return {
    pageTitle: document.title || "",
    selectedText: getSelectedText().slice(0, maxVisibleTextLength),
    visibleText: getVisibleBodyText().slice(0, maxVisibleTextLength),
    forms: collectFormMetadata(),
    links: collectVisibleLinks(),
    messageCandidates: collectMessageCandidates()
  };
}

async function analyzePage(payload) {
  const response = await fetch(PAGE_API_URL, {
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

async function analyzeMessage(payload) {
  const response = await fetch(MESSAGE_API_URL, {
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
  repeatNoteElement.hidden = true;
  messagePreviewElement.hidden = true;
  nearbyThreatsElement.hidden = true;
  loadingStateElement.hidden = false;
  statusElement.textContent = "Analyzing URL and page content signals...";
}

function showError(title, message, backendStatus = "offline") {
  setBackendStatus(backendStatus);
  loadingStateElement.hidden = true;
  resultElement.hidden = true;
  repeatNoteElement.hidden = true;
  messagePreviewElement.hidden = true;
  nearbyThreatsElement.hidden = true;
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
  let animationIndex = 0;

  if (result.trust_signals?.length > 0) {
    reasonsElement.appendChild(
      createReasonGroup("Trust Signals", result.trust_signals, "low", animationIndex)
    );
    animationIndex += result.trust_signals.length;
  }

  const signalGroups = getSignalGroups(result);
  const hasGroupedSignals = signalGroups.some((group) => group.reasons.length > 0);

  if (hasGroupedSignals) {
    signalGroups.forEach((group) => {
      if (group.reasons.length === 0) {
        return;
      }

      reasonsElement.appendChild(
        createReasonGroup(group.title, group.reasons, riskLevel, animationIndex)
      );
      animationIndex += group.reasons.length;
    });

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

function getSignalGroups(result) {
  const signals = result.signals || {};

  if ("sender_signals" in signals || "message_signals" in signals) {
    return [
      { title: "Sender signals", reasons: signals.sender_signals || [] },
      { title: "Message signals", reasons: signals.message_signals || [] },
      { title: "Link signals", reasons: signals.link_signals || [] },
      { title: "Repeat signals", reasons: signals.repeat_signals || [] }
    ];
  }

  return [
    { title: "URL signals", reasons: signals.url_signals || [] },
    { title: "Page content signals", reasons: signals.content_signals || [] },
    { title: "Form signals", reasons: signals.form_signals || [] }
  ];
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
  renderRepeatNote(result);
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

function renderRepeatNote(result) {
  if (result.repeat_count > 1) {
    repeatNoteElement.textContent = `Similar message scans on this device: ${result.repeat_count}`;
    repeatNoteElement.hidden = false;
    return;
  }

  if (result.confidence) {
    repeatNoteElement.textContent = `Detection confidence: ${capitalize(result.confidence)}`;
    repeatNoteElement.hidden = false;
    return;
  }

  repeatNoteElement.hidden = true;
}

function capitalize(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
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
    latestScanType = "website";
    renderResult(result);
  } catch (error) {
    showError(
      "Backend unavailable",
      "Backend unavailable. Start the FastAPI server and try again."
    );
  }
}

async function scanEmailMessage() {
  showLoading();
  statusElement.textContent = "Detecting visible message candidates...";

  try {
    const tab = await getCurrentTab();
    currentTabUrl = tab?.url || "";
    currentUrlElement.textContent = currentTabUrl || "No supported URL found.";
    currentUrlElement.title = currentTabUrl;

    if (!currentTabUrl.startsWith("http://") && !currentTabUrl.startsWith("https://")) {
      showError(
        "Unsupported page",
        "Open an HTTP or HTTPS page to analyze selected or visible message text.",
        "checking"
      );
      return;
    }

    const pageContent = await collectPageContent(tab);
    prepareMessageCandidates(pageContent, currentTabUrl);
    renderMessageCandidatePreview();

    const candidate = getSelectedCandidate();
    const result = await scanMessageCandidate(candidate, pageContent);

    latestScanType = "message";
    renderResult(result);
  } catch (error) {
    showError(
      "Backend unavailable",
      "Backend unavailable. Start the FastAPI server and try again."
    );
  }
}

async function scanMessageCandidate(candidate, pageContent) {
  statusElement.textContent = "Analyzing selected message only...";
  const sender = senderInputElement.value.trim() || candidate?.sender || "";
  return analyzeMessage({
    source_url: candidate?.source_url || currentTabUrl,
    subject: candidate?.subject || pageContent.page_title,
    sender,
    sender_type: detectSenderType(sender),
    message_text: candidate?.message_text || pageContent.selected_text || pageContent.visible_text,
    links: candidate?.links || pageContent.links
  });
}

function prepareMessageCandidates(pageContent, sourceUrl) {
  messageCandidates = pageContent.message_candidates || [];

  if (messageCandidates.length === 0) {
    messageCandidates = [{
      candidate_id: "visible-page",
      sender: senderInputElement.value.trim(),
      subject: pageContent.page_title,
      preview: (pageContent.selected_text || pageContent.visible_text).slice(0, 300),
      message_text: pageContent.selected_text || pageContent.visible_text,
      links: pageContent.links,
      source_url: sourceUrl,
      confidence_score: 1,
      contains_selection: Boolean(pageContent.selected_text),
      position: { top: 0, left: 0, width: 0, height: 0 }
    }];
  }

  const selectedCandidate = messageCandidates.find((candidate) => candidate.contains_selection);
  selectedMessageCandidateId = (
    selectedCandidate ||
    (messageCandidates.length === 1 ? messageCandidates[0] : [...messageCandidates].sort((a, b) => a.position.top - b.position.top)[0])
  )?.candidate_id;
}

function getSelectedCandidate() {
  return messageCandidates.find((candidate) => candidate.candidate_id === selectedMessageCandidateId) || messageCandidates[0];
}

function renderMessageCandidatePreview() {
  const candidate = getSelectedCandidate();
  const nearbyThreats = messageCandidates
    .filter((item) => item.candidate_id !== candidate?.candidate_id)
    .map((item) => ({ ...item, nearbyRisk: estimateNearbyRisk(item) }))
    .filter((item) => item.nearbyRisk.level !== "low");

  messagePreviewElement.innerHTML = "";
  messagePreviewElement.appendChild(createCandidateCard(candidate, true));
  messagePreviewElement.hidden = false;

  nearbyThreatsElement.innerHTML = "";
  if (messageCandidates.length > 1) {
    const summary = document.createElement("div");
    summary.className = "nearby-alert";
    summary.textContent = `Detected ${messageCandidates.length} visible messages`;
    nearbyThreatsElement.appendChild(summary);
  }

  if (nearbyThreats.length > 0) {
    const heading = document.createElement("span");
    heading.className = "nearby-heading";
    heading.textContent = `${nearbyThreats.length} other visible message${nearbyThreats.length === 1 ? "" : "s"} may be risky.`;
    nearbyThreatsElement.appendChild(heading);

    nearbyThreats.forEach((threat) => {
      nearbyThreatsElement.appendChild(createCandidateCard(threat, false, threat.nearbyRisk.level));
    });
  }

  nearbyThreatsElement.hidden = nearbyThreatsElement.childElementCount === 0;
}

function createCandidateCard(candidate, isPrimary, roughRiskLabel = "") {
  const card = document.createElement("div");
  card.className = "candidate-card";
  const linkCount = candidate?.links?.length || 0;

  card.innerHTML = `
    <strong>${isPrimary ? "Primary selected message" : "Other Nearby Threat"}</strong>
    <p class="candidate-meta">Sender: ${escapeHtml(candidate?.sender || senderInputElement.value.trim() || "Unknown")}</p>
    <p class="candidate-meta">Subject: ${escapeHtml(candidate?.subject || "Unknown")}</p>
    <p class="candidate-preview">${escapeHtml(candidate?.preview || "")}</p>
    <p class="candidate-meta">Links: ${linkCount}${roughRiskLabel ? ` · Rough risk: ${roughRiskLabel}` : ""}</p>
  `;

  const actions = document.createElement("div");
  actions.className = "candidate-actions";

  const scanButton = document.createElement("button");
  scanButton.className = "mini-button";
  scanButton.type = "button";
  scanButton.textContent = isPrimary ? "Scan This Message" : "Scan this message";
  scanButton.addEventListener("click", async () => {
    selectedMessageCandidateId = candidate.candidate_id;
    await scanSelectedCandidateOnly();
  });
  actions.appendChild(scanButton);

  if (messageCandidates.length > 1) {
    const chooseButton = document.createElement("button");
    chooseButton.className = "mini-button";
    chooseButton.type = "button";
    chooseButton.textContent = "Choose Another Message";
    chooseButton.addEventListener("click", () => {
      const currentIndex = messageCandidates.findIndex((item) => item.candidate_id === selectedMessageCandidateId);
      const nextIndex = (currentIndex + 1) % messageCandidates.length;
      selectedMessageCandidateId = messageCandidates[nextIndex].candidate_id;
      renderMessageCandidatePreview();
    });
    actions.appendChild(chooseButton);
  }

  card.appendChild(actions);
  return card;
}

async function scanSelectedCandidateOnly() {
  showLoading();
  const candidate = getSelectedCandidate();
  const pageContent = {
    page_title: candidate?.subject || document.title || "",
    selected_text: "",
    visible_text: candidate?.message_text || "",
    links: candidate?.links || []
  };
  renderMessageCandidatePreview();
  const result = await scanMessageCandidate(candidate, pageContent);
  latestScanType = "message";
  renderResult(result);
}

function estimateNearbyRisk(candidate) {
  const text = `${candidate.sender} ${candidate.subject} ${candidate.message_text}`.toLowerCase();
  let score = 0;
  if (/(urgent|immediately|final warning|respond now)/.test(text)) score += 2;
  if (/(suspended|account locked|locked|payment failed|unusual activity)/.test(text)) score += 2;
  if (/(verify password|password|security code|login now)/.test(text)) score += 2;
  if (candidate.links?.some((link) => link.href.startsWith("http://") || /(login|verify|secure)/i.test(link.href))) score += 2;
  if (/(gmail\.com|yahoo\.com|outlook\.com)/.test(candidate.sender || "") && /(google|chase|paypal|bank|security)/.test(text)) score += 2;

  if (score >= 5) return { level: "high" };
  if (score >= 3) return { level: "medium" };
  return { level: "low" };
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}

function detectSenderType(sender) {
  if (!sender) {
    return "unknown";
  }
  if (sender.includes("@")) {
    return "email";
  }
  if (/^\+?[\d\s().-]{7,}$/.test(sender)) {
    return "phone";
  }
  return "unknown";
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
  const senderSignals = latestResult?.signals?.sender_signals?.length
    ? latestResult.signals.sender_signals.join("\n- ")
    : "None";
  const messageSignals = latestResult?.signals?.message_signals?.length
    ? latestResult.signals.message_signals.join("\n- ")
    : "None";
  const linkSignals = latestResult?.signals?.link_signals?.length
    ? latestResult.signals.link_signals.join("\n- ")
    : "None";
  const repeatSignals = latestResult?.signals?.repeat_signals?.length
    ? latestResult.signals.repeat_signals.join("\n- ")
    : "None";
  const trustSignals = latestResult?.trust_signals?.length
    ? latestResult.trust_signals.join("\n- ")
    : "None";

  return `TrustTrace AI Scan Report
Scan Type: ${latestScanType}
URL: ${latestResult?.url || currentTabUrl}
Risk Level: ${latestResult?.risk_level || "Unavailable"}
Trust Score: ${latestResult?.trust_score ?? "Unavailable"}
Phishing Probability: ${Math.round((latestResult?.phishing_probability || 0) * 100)}%
Detection Confidence: ${latestResult?.confidence || "N/A"}
Repeat Count: ${latestResult?.repeat_count || "N/A"}
Reasons:
- ${reasons}
Trust Signals:
- ${trustSignals}
URL Signals:
- ${urlSignals}
Page Content Signals:
- ${contentSignals}
Form Signals:
- ${formSignals}
Sender Signals:
- ${senderSignals}
Message Signals:
- ${messageSignals}
Link Signals:
- ${linkSignals}
Repeat Signals:
- ${repeatSignals}`;
}

rescanButton.addEventListener("click", scanCurrentUrl);
scanMessageButton.addEventListener("click", scanEmailMessage);

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

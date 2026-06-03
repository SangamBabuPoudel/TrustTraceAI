const URL_API_URL = "http://127.0.0.1:8000/api/analyze-url";
const PAGE_API_URL = "http://127.0.0.1:8000/api/analyze-page";
const MESSAGE_API_URL = "http://127.0.0.1:8000/api/analyze-message";
const MAX_VISIBLE_TEXT_LENGTH = 5000;
const LINK_SCAN_CONCURRENCY = 4;
const CLIPBOARD_GUARDIAN_SETTING_KEY = "trusttraceClipboardGuardianEnabled";

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
const attackExplanationElement = document.getElementById("attack-explanation");
const attackBodyElement = document.getElementById("attack-body");
const visualClonePanelElement = document.getElementById("visual-clone-panel");
const visualCloneScoreElement = document.getElementById("visual-clone-score");
const visualCloneConfidenceElement = document.getElementById("visual-clone-confidence");
const visualCloneBrandElement = document.getElementById("visual-clone-brand");
const visualCloneSignalsElement = document.getElementById("visual-clone-signals");
const rescanButton = document.getElementById("rescan");
const copyUrlButton = document.getElementById("copy-url");
const copyReportButton = document.getElementById("copy-report");
const scanMessageButton = document.getElementById("scan-message");
const scanLinksButton = document.getElementById("scan-links");
const senderInputElement = document.getElementById("sender-input");
const messagePreviewElement = document.getElementById("message-preview");
const nearbyThreatsElement = document.getElementById("nearby-threats");
const linkScanPanelElement = document.getElementById("link-scan-panel");
const clipboardToggleElement = document.getElementById("clipboard-toggle");
const clipboardToggleLabelElement = document.getElementById("clipboard-toggle-label");
const scanClipboardButton = document.getElementById("scan-clipboard");
const clipboardResultElement = document.getElementById("clipboard-result");
const securityReportGridElement = document.getElementById("security-report-grid");
const reportMessageElement = document.getElementById("report-message");
const refreshReportButton = document.getElementById("refresh-report");
const resetReportButton = document.getElementById("reset-report");

let currentTabUrl = "";
let latestResult = null;
let latestScanType = "website";
let messageCandidates = [];
let selectedMessageCandidateId = null;
const popupLinkCache = new Map();

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
      visual_metadata: getEmptyVisualMetadata(),
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
      args: [MAX_VISIBLE_TEXT_LENGTH, clipboardToggleElement?.checked || false]
    });

    return normalizePageContent(result?.result, tab);
  } catch (error) {
    return {
      page_title: tab?.title || "",
      selected_text: "",
      visible_text: "",
      forms: [],
      links: [],
      visual_metadata: getEmptyVisualMetadata(),
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
    visual_metadata: pageContent?.visualMetadata || getEmptyVisualMetadata(),
    clipboard_signals: pageContent?.clipboardSignals || [],
    message_candidates: pageContent?.messageCandidates || []
  };
}

function getEmptyVisualMetadata() {
  return {
    document_title: "",
    primary_headings: [],
    favicons: [],
    images: [],
    logo_candidates: [],
    button_texts: [],
    input_labels: [],
    brand_like_text: [],
    color_hints: [],
    layout_hints: {
      has_centered_login_card: false,
      has_fullscreen_login_layout: false,
      has_minimal_login_page: false
    }
  };
}

function collectTrustTracePageSnapshot(maxVisibleTextLength, clipboardGuardianEnabledForSnapshot) {
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

  function detectClipboardSignalsFallback() {
    const terms = [
      "copy address",
      "copy wallet",
      "copy code",
      "paste code",
      "paste otp",
      "paste security code",
      "paste password",
      "recovery phrase",
      "seed phrase",
      "private key",
      "wallet address",
      "verification code",
      "authentication code",
      "one-time code",
      "payment address",
      "crypto address"
    ];
    const bodyText = (document.body?.innerText || "").replace(/\s+/g, " ").toLowerCase();
    return terms
      .filter((term) => bodyText.includes(term))
      .map((term) => `Page contains clipboard-sensitive language: ${term}.`)
      .slice(0, 8);
  }

  function cleanText(value) {
    return String(value || "").replace(/\s+/g, " ").trim();
  }

  function cssEscapeFallback(value) {
    if (window.CSS?.escape) {
      return window.CSS.escape(value);
    }
    return String(value).replace(/["\\]/g, "\\$&");
  }

  function getNearbyText(element, maxLength) {
    const container = element.closest("header, main, section, article, form, div") || element.parentElement || element;
    return cleanText(container.innerText || container.textContent || "").slice(0, maxLength);
  }

  function collectVisualMetadata() {
    const brandTerms = [
      "apple", "apple id", "icloud", "google", "gmail", "youtube", "openai", "chatgpt",
      "claude", "anthropic", "microsoft", "outlook", "office", "paypal", "amazon",
      "netflix", "facebook", "instagram", "github", "chase", "bank of america",
      "wells fargo", "dhl", "fedex", "usps"
    ];
    const images = Array.from(document.images || [])
      .filter((image) => {
        const rect = image.getBoundingClientRect();
        const style = window.getComputedStyle(image);
        return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
      })
      .slice(0, 30)
      .map((image) => {
        const rect = image.getBoundingClientRect();
        return {
          src: image.currentSrc || image.src || image.getAttribute("src") || "",
          alt: image.getAttribute("alt") || "",
          title: image.getAttribute("title") || "",
          class_name: image.className ? String(image.className) : "",
          id: image.id || "",
          width: Math.round(rect.width || image.naturalWidth || image.width || 0),
          height: Math.round(rect.height || image.naturalHeight || image.height || 0),
          nearby_text: getNearbyText(image, 150)
        };
      });
    const logoCandidates = images.filter((image) => {
      const combined = `${image.src} ${image.alt} ${image.title} ${image.class_name} ${image.id} ${image.nearby_text}`.toLowerCase();
      return combined.includes("logo") || brandTerms.some((term) => combined.includes(term));
    }).slice(0, 10);
    const visibleInputs = Array.from(document.querySelectorAll("input")).filter((input) => {
      const rect = input.getBoundingClientRect();
      const style = window.getComputedStyle(input);
      return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
    });
    const passwordInput = visibleInputs.find((input) => input.type === "password");
    const emailInput = visibleInputs.find(isEmailOrUsernameInput);
    const loginContainer = passwordInput?.closest("form, main, section, article, div") || null;
    const rect = loginContainer?.getBoundingClientRect?.();
    const bodyText = cleanText(document.body?.innerText || "");
    const pageText = cleanText(`${document.title || ""} ${bodyText.slice(0, 2500)}`);

    return {
      document_title: document.title || "",
      primary_headings: Array.from(document.querySelectorAll("h1, h2, h3"))
        .filter((heading) => {
          const headingRect = heading.getBoundingClientRect();
          const style = window.getComputedStyle(heading);
          return headingRect.width > 0 && headingRect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
        })
        .map((heading) => cleanText(heading.innerText || heading.textContent || ""))
        .filter(Boolean)
        .slice(0, 20),
      favicons: Array.from(document.querySelectorAll("link[rel*='icon' i], link[rel='apple-touch-icon' i]"))
        .slice(0, 10)
        .map((link) => ({
          href: link.href || link.getAttribute("href") || "",
          type: link.getAttribute("type") || "",
          rel: link.getAttribute("rel") || ""
        })),
      images,
      logo_candidates: logoCandidates,
      button_texts: Array.from(document.querySelectorAll("button, input[type='submit'], input[type='button'], a[role='button']"))
        .map((button) => cleanText(button.innerText || button.value || button.getAttribute("aria-label") || ""))
        .filter(Boolean)
        .slice(0, 40),
      input_labels: visibleInputs.map((input) => {
        const explicitLabel = input.id ? document.querySelector(`label[for="${cssEscapeFallback(input.id)}"]`) : null;
        const wrapperLabel = input.closest("label");
        return cleanText([
          explicitLabel?.innerText || "",
          wrapperLabel?.innerText || "",
          input.getAttribute("placeholder") || "",
          input.getAttribute("aria-label") || "",
          input.getAttribute("name") || "",
          input.id || ""
        ].join(" "));
      }).filter(Boolean).slice(0, 40),
      brand_like_text: brandTerms.filter((term) => pageText.toLowerCase().includes(term)).slice(0, 20),
      color_hints: [],
      layout_hints: {
        has_centered_login_card: Boolean(rect && passwordInput && rect.width > 220 && rect.width < Math.min(window.innerWidth, 620) && Math.abs((rect.left + rect.width / 2) - (window.innerWidth / 2)) < window.innerWidth * 0.22),
        has_fullscreen_login_layout: Boolean(passwordInput && emailInput && bodyText.length < 4000),
        has_minimal_login_page: Boolean(passwordInput && visibleInputs.length <= 8 && bodyText.length < 2200)
      }
    };
  }

  return {
    pageTitle: document.title || "",
    selectedText: getSelectedText().slice(0, maxVisibleTextLength),
    visibleText: getVisibleBodyText().slice(0, maxVisibleTextLength),
    forms: collectFormMetadata(),
    links: collectVisibleLinks(),
    visualMetadata: collectVisualMetadata(),
    clipboardSignals: clipboardGuardianEnabledForSnapshot ? detectClipboardSignalsFallback() : [],
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

async function analyzeUrlOnly(url) {
  const normalizedUrl = normalizeHref(url);
  if (popupLinkCache.has(normalizedUrl)) {
    return popupLinkCache.get(normalizedUrl);
  }

  const response = await fetch(URL_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url: normalizedUrl })
  });

  if (!response.ok) {
    throw new Error("The local TrustTrace API returned an error.");
  }

  const result = await response.json();
  popupLinkCache.set(normalizedUrl, result);
  return result;
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
  attackExplanationElement.hidden = true;
  visualClonePanelElement.hidden = true;
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
  attackExplanationElement.hidden = true;
  visualClonePanelElement.hidden = true;
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
  const deepSignals = (result.deep_analysis?.signals || []).map((signal) => {
    if (typeof signal === "string") {
      return signal;
    }
    return signal.message || "Deep URL heuristic signal detected.";
  });
  const threatIntelSignals = result.threat_intel?.is_known_bad
    ? [result.threat_intel.reason || "URL matched configured local threat intelligence."]
    : [];

  if ("sender_signals" in signals || "message_signals" in signals) {
    return [
      { title: "Sender signals", reasons: signals.sender_signals || [] },
      { title: "Message signals", reasons: signals.message_signals || [] },
      { title: "Link signals", reasons: signals.link_signals || [] },
      { title: "Repeat signals", reasons: signals.repeat_signals || [] }
    ];
  }

  return [
    { title: "Threat Intelligence", reasons: threatIntelSignals },
    { title: "Deep URL Signals", reasons: deepSignals },
    { title: "URL signals", reasons: signals.url_signals || [] },
    { title: "Clipboard Signals", reasons: signals.clipboard_signals || [] },
    { title: "Visual Clone Signals", reasons: signals.visual_clone_signals || [] },
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
  renderAttackExplanation(result.attack_explanation);
  renderVisualClone(result.visual_clone);
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

function renderVisualClone(visualClone) {
  const score = Number(visualClone?.visual_clone_score || 0);
  const signals = visualClone?.signals || [];
  const shouldShow = score >= 40 || signals.length > 0 || Boolean(visualClone?.is_visual_clone_suspected);

  if (!shouldShow) {
    visualClonePanelElement.hidden = true;
    return;
  }

  const confidence = capitalize(visualClone.visual_clone_confidence || "low");
  const brand = visualClone.primary_clone_brand || (visualClone.claimed_brands || [])[0] || "Unknown";

  visualClonePanelElement.hidden = false;
  visualClonePanelElement.className = `visual-clone-panel ${visualClone.visual_clone_confidence || "low"}`;
  visualCloneScoreElement.textContent = `${score}/100`;
  visualCloneConfidenceElement.textContent = `Confidence: ${confidence}`;
  visualCloneBrandElement.textContent = `Claimed brand: ${capitalize(String(brand))}`;
  visualCloneSignalsElement.innerHTML = signals
    .slice(0, 4)
    .map((signal) => `<span>${escapeHtml(signal.message || "Visual clone signal detected.")}</span>`)
    .join("");
}

function renderAttackExplanation(explanation) {
  if (!explanation) {
    attackExplanationElement.hidden = true;
    return;
  }

  const isLowRisk = explanation.attack_type === "Unknown / low-risk";
  attackExplanationElement.hidden = false;
  attackExplanationElement.open = !isLowRisk;

  const howItWorks = (explanation.how_it_works || []).slice(0, 3);
  const whatToAvoid = (explanation.what_to_avoid || []).slice(0, 3);

  attackBodyElement.innerHTML = `
    <div class="attack-type-row">
      <span>${escapeHtml(explanation.attack_type || "Unknown / low-risk")}</span>
      <strong class="${escapeHtml(explanation.severity || "low")}">${escapeHtml(explanation.severity || "low")}</strong>
    </div>
    <p>${escapeHtml(explanation.summary || "No strong attack pattern identified.")}</p>
    ${howItWorks.length ? `<h3>How it works</h3><ul>${howItWorks.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}
    ${whatToAvoid.length ? `<h3>What to avoid</h3><ul>${whatToAvoid.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}
    ${explanation.safer_action ? `<h3>Safer action</h3><p>${escapeHtml(explanation.safer_action)}</p>` : ""}
  `;
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
      forms: pageContent.forms,
      visual_metadata: pageContent.visual_metadata
    });
    applyClipboardSignalsToPageResult(result, pageContent.clipboard_signals);
    latestScanType = "website";
    renderResult(result);
    await TrustTraceSecurityStats.recordScanResult(result, "website");
    await renderSecurityReport();
  } catch (error) {
    showError(
      "Backend unavailable",
      "Backend unavailable. Start the FastAPI server and try again."
    );
  }
}

function applyClipboardSignalsToPageResult(result, clipboardSignals) {
  if (!clipboardSignals?.length) {
    return;
  }

  result.signals = {
    ...(result.signals || {}),
    clipboard_signals: clipboardSignals
  };
  result.reasons = [
    ...(result.reasons || []),
    "Clipboard-related sensitive action detected.",
    ...clipboardSignals
  ];
}

async function initializeClipboardGuardianControls() {
  const stored = await chrome.storage.local.get(CLIPBOARD_GUARDIAN_SETTING_KEY);
  const enabled = Boolean(stored[CLIPBOARD_GUARDIAN_SETTING_KEY]);
  clipboardToggleElement.checked = enabled;
  updateClipboardToggleLabel(enabled);
}

async function setClipboardGuardianEnabled(enabled) {
  await chrome.storage.local.set({ [CLIPBOARD_GUARDIAN_SETTING_KEY]: enabled });
  updateClipboardToggleLabel(enabled);
}

function updateClipboardToggleLabel(enabled) {
  clipboardToggleLabelElement.textContent = enabled ? "On" : "Off";
}

async function scanClipboardNow() {
  clipboardResultElement.hidden = false;

  if (!clipboardToggleElement.checked) {
    renderClipboardResult({
      risk_level: "low",
      detected_type: "Clipboard Guardian is off",
      reasons: ["Turn Clipboard Guardian on before scanning clipboard content."],
      safer_action: "Enable Clipboard Guardian when you want a local clipboard safety check."
    });
    return;
  }

  try {
    const clipboardText = await navigator.clipboard.readText();
    const isUrl = /^https?:\/\//i.test(clipboardText.trim());
    let urlResult = null;

    if (isUrl) {
      try {
        urlResult = await analyzeUrlOnly(clipboardText.trim());
      } catch (error) {
        urlResult = null;
      }
    }

    const result = TrustTraceClipboardGuardian.analyzeClipboardText(clipboardText, urlResult);
    renderClipboardResult(result);
    await TrustTraceSecurityStats.recordClipboardScanResult(result, { urlScanned: isUrl });
    await renderSecurityReport();
  } catch (error) {
    renderClipboardResult({
      risk_level: "medium",
      detected_type: "Clipboard unavailable",
      reasons: ["Clipboard could not be read. Use the browser permission prompt and try again."],
      safer_action: "Scan only when you intentionally want TrustTrace to inspect current clipboard text locally."
    });
  }
}

function renderClipboardResult(result) {
  const riskLevel = result.risk_level || "low";
  clipboardResultElement.hidden = false;
  clipboardResultElement.className = `clipboard-result ${riskLevel}`;
  clipboardResultElement.innerHTML = `
    <div class="clipboard-result-top">
      <span>Clipboard Risk Level: ${escapeHtml(capitalize(riskLevel))}</span>
      <strong>${escapeHtml(result.detected_type || "No obvious clipboard threat")}</strong>
    </div>
    <ul>${(result.reasons || []).map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>
    <p>${escapeHtml(result.safer_action || "Review clipboard content before pasting it into sensitive pages.")}</p>
  `;
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
    await TrustTraceSecurityStats.recordMessageScanResult(result);
    await renderSecurityReport();
  } catch (error) {
    showError(
      "Backend unavailable",
      "Backend unavailable. Start the FastAPI server and try again."
    );
  }
}

async function scanLinksOnPage() {
  const tab = await getCurrentTab();
  currentTabUrl = tab?.url || "";
  currentUrlElement.textContent = currentTabUrl || "No supported URL found.";
  currentUrlElement.title = currentTabUrl;

  if (!currentTabUrl.startsWith("http://") && !currentTabUrl.startsWith("https://")) {
    renderLinkScanError("Open an HTTP or HTTPS page to scan visible links.");
    return;
  }

  setBackendStatus("checking");
  scanLinksButton.disabled = true;
  renderLinkScanProgress(0, 0, "Collecting visible links...");

  try {
    const snapshot = await extractVisibleLinksFromTab(tab, getLinkExtractionMode(currentTabUrl));
    const links = dedupeLinks(snapshot.links || []).slice(0, 30);

    if (links.length === 0) {
      renderLinkScanError("No visible scan-worthy links were found on this page.", "checking");
      return;
    }

    renderLinkScanProgress(0, links.length, "Scanning visible link URLs...");
    const scanned = await scanLinksWithLimit(links, LINK_SCAN_CONCURRENCY, (completed, total) => {
      renderLinkScanProgress(completed, total, `Scanning ${completed} of ${total} links...`);
    });

    setBackendStatus("online");
    renderLinkScanSummary(scanned);
  } catch (error) {
    renderLinkScanError("Backend unavailable. Start the FastAPI server and try again.");
  } finally {
    scanLinksButton.disabled = false;
  }
}

async function extractVisibleLinksFromTab(tab, mode) {
  try {
    return await chrome.tabs.sendMessage(tab.id, {
      type: "TRUSTTRACE_EXTRACT_VISIBLE_LINKS",
      mode
    });
  } catch (error) {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: collectVisibleLinksFallback,
      args: [mode]
    });
    return result?.result || { links: [], page_url: tab.url, page_title: tab.title, mode };
  }
}

function collectVisibleLinksFallback(mode) {
  const maxLinks = mode === "search" ? 15 : 30;
  const seen = new Set();

  function isVisible(element) {
    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);
    return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
  }

  const links = Array.from(document.querySelectorAll("a[href]"))
    .filter((link) => {
      try {
        const url = new URL(link.href);
        if (!["http:", "https:"].includes(url.protocol) || seen.has(url.href) || !isVisible(link)) {
          return false;
        }
        seen.add(url.href);
        return true;
      } catch (error) {
        return false;
      }
    })
    .slice(0, maxLinks)
    .map((link, index) => {
      const url = new URL(link.href);
      const text = (link.innerText || link.textContent || link.href).replace(/\s+/g, " ").trim();
      return {
        id: `fallback-link-${index + 1}`,
        href: url.href,
        text: text.slice(0, 160),
        hostname: url.hostname,
        context: text.slice(0, 150),
        is_search_result: mode === "search",
        is_message_link: false
      };
    });

  return {
    links,
    page_url: window.location.href,
    page_title: document.title || "",
    mode
  };
}

async function scanLinksWithLimit(links, limit, onProgress) {
  const results = [];
  let nextIndex = 0;
  let completed = 0;

  async function worker() {
    while (nextIndex < links.length) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      const link = links[currentIndex];

      try {
        const result = await analyzeUrlOnly(link.href);
        results[currentIndex] = {
          link,
          result,
          status: "ok",
          classification: classifyLinkResult(result)
        };
      } catch (error) {
        results[currentIndex] = {
          link,
          result: null,
          status: "failed",
          classification: { level: "unknown", label: "Unknown" }
        };
      }

      completed += 1;
      onProgress(completed, links.length);
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, links.length) }, worker));
  return results;
}

function classifyLinkResult(result) {
  const trustScore = Number(result?.trust_score);
  const probability = Number(result?.phishing_probability);

  if (
    trustScore <= 30 ||
    probability >= 0.75 ||
    result?.risk_level === "high"
  ) {
    return { level: "high", label: "High Risk" };
  }
  if ((trustScore > 30 && trustScore <= 60) || result?.risk_level === "medium") {
    return { level: "caution", label: "Caution" };
  }
  if (trustScore >= 80) {
    return { level: "trusted", label: "Trusted" };
  }
  return { level: "low", label: "Low/Neutral" };
}

function renderLinkScanProgress(completed, total, message) {
  linkScanPanelElement.hidden = false;
  linkScanPanelElement.innerHTML = `
    <div class="link-progress">
      <span>${escapeHtml(message)}</span>
      <strong>${total ? `${completed}/${total}` : ""}</strong>
    </div>
    <div class="link-progress-track"><span style="width:${total ? Math.round((completed / total) * 100) : 12}%;"></span></div>
  `;
}

function renderLinkScanError(message, backendStatus = "offline") {
  setBackendStatus(backendStatus);
  linkScanPanelElement.hidden = false;
  linkScanPanelElement.innerHTML = `<div class="link-scan-empty">${escapeHtml(message)}</div>`;
}

function renderLinkScanSummary(scanned) {
  const summary = {
    total: scanned.length,
    trusted: scanned.filter((item) => item.classification.level === "trusted" || item.classification.level === "low").length,
    caution: scanned.filter((item) => item.classification.level === "caution").length,
    high: scanned.filter((item) => item.classification.level === "high").length,
    unknown: scanned.filter((item) => item.classification.level === "unknown").length
  };
  TrustTraceSecurityStats.recordLinkScanSummary(summary).then(renderSecurityReport);
  const riskyLinks = scanned
    .filter((item) => item.classification.level === "high" || item.classification.level === "caution")
    .sort((a, b) => Number(a.result?.trust_score ?? 101) - Number(b.result?.trust_score ?? 101))
    .slice(0, 5);

  linkScanPanelElement.hidden = false;
  linkScanPanelElement.innerHTML = "";

  const summaryGrid = document.createElement("div");
  summaryGrid.className = "link-summary-grid";
  [
    ["Total", summary.total],
    ["Trusted/Low", summary.trusted],
    ["Caution", summary.caution],
    ["High Risk", summary.high],
    ["Unknown", summary.unknown]
  ].forEach(([label, value]) => {
    const item = document.createElement("div");
    item.className = "link-summary-item";
    item.innerHTML = `<span>${label}</span><strong>${value}</strong>`;
    summaryGrid.appendChild(item);
  });
  linkScanPanelElement.appendChild(summaryGrid);

  const heading = document.createElement("span");
  heading.className = "link-risk-heading";
  heading.textContent = riskyLinks.length ? "Top risky links" : "No caution or high-risk links found.";
  linkScanPanelElement.appendChild(heading);

  riskyLinks.forEach((item) => {
    linkScanPanelElement.appendChild(createRiskyLinkCard(item));
  });
}

async function renderSecurityReport() {
  const stats = await TrustTraceSecurityStats.getSecurityStats();
  const mostCommonAttack = getMostCommonAttack(stats.attack_type_counts);
  const riskyItems = (
    Number(stats.high_risk_blocks || 0)
    + Number(stats.medium_cautions || 0)
    + Number(stats.high_risk_links_detected || 0)
    + Number(stats.suspicious_messages_detected || 0)
    + Number(stats.fake_login_forms_detected || 0)
    + Number(stats.visual_clone_warnings || 0)
  );

  const reportItems = [
    ["URLs scanned", stats.total_url_scans],
    ["High-risk blocked", stats.high_risk_blocks],
    ["Cautions shown", stats.medium_cautions],
    ["Suspicious messages", stats.suspicious_messages_detected],
    ["High-risk links", stats.high_risk_links_detected],
    ["Fake login forms", stats.fake_login_forms_detected],
    ["Visual clone warnings", stats.visual_clone_warnings],
    ["High-confidence clones", stats.high_confidence_visual_clones],
    ["Branded login clones", stats.branded_login_clone_detections],
    ["Repeated scams", stats.repeated_message_warnings],
    ["Clipboard scans", stats.clipboard_scans],
    ["Clipboard warnings", stats.clipboard_warnings],
    ["Clipboard high risk", stats.clipboard_high_risk_findings],
    ["Copy mismatches", stats.clipboard_mismatch_warnings],
    ["Top attack", mostCommonAttack]
  ];

  securityReportGridElement.innerHTML = "";
  reportItems.forEach(([label, value]) => {
    const item = document.createElement("div");
    item.className = "security-stat";
    item.innerHTML = `<span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value || 0))}</strong>`;
    securityReportGridElement.appendChild(item);
  });

  reportMessageElement.textContent = riskyItems > 0
    ? `TrustTrace AI helped you identify ${riskyItems} risky item${riskyItems === 1 ? "" : "s"}.`
    : "No risky items have been recorded in your local report yet.";
}

function getMostCommonAttack(attackTypeCounts) {
  const entries = Object.entries(attackTypeCounts || {})
    .filter(([, count]) => Number(count) > 0)
    .sort((a, b) => Number(b[1]) - Number(a[1]));
  return entries[0]?.[0] || "None yet";
}

async function resetLocalSecurityReport() {
  const shouldReset = confirm("Reset local TrustTrace Report Card stats for this browser?");
  if (!shouldReset) {
    return;
  }

  await TrustTraceSecurityStats.resetSecurityStats();
  await renderSecurityReport();
}

function createRiskyLinkCard(item) {
  const card = document.createElement("div");
  card.className = `risky-link-card ${item.classification.level}`;
  const topReason = item.result?.reasons?.[0] || "No specific reason returned.";
  const attackType = item.result?.attack_explanation?.attack_type;
  const title = item.link.text || item.link.hostname || item.link.href;

  card.innerHTML = `
    <strong>${escapeHtml(title)}</strong>
    <p>${escapeHtml(item.link.hostname)} · ${escapeHtml(item.classification.label)} · Trust score ${item.result?.trust_score ?? "N/A"}${attackType ? ` · ${escapeHtml(attackType)}` : ""}</p>
    <p>${escapeHtml(topReason)}</p>
  `;

  const actions = document.createElement("div");
  actions.className = "candidate-actions";

  const copyButton = document.createElement("button");
  copyButton.className = "mini-button";
  copyButton.type = "button";
  copyButton.textContent = "Copy URL";
  copyButton.addEventListener("click", () => copyText(item.link.href, copyButton, "Copied"));
  actions.appendChild(copyButton);

  if (item.classification.level === "high") {
    const warningButton = document.createElement("button");
    warningButton.className = "mini-button";
    warningButton.type = "button";
    warningButton.textContent = "Open Warning Report";
    warningButton.addEventListener("click", async () => {
      const tab = await getCurrentTab();
      await chrome.runtime.sendMessage({
        type: "TRUSTTRACE_OPEN_WARNING_FOR_URL",
        tab_id: tab?.id,
        url: item.link.href,
        result: item.result
      });
    });
    actions.appendChild(warningButton);
  }

  card.appendChild(actions);
  return card;
}

function getLinkExtractionMode(url) {
  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname.toLowerCase();
    if (
      ((hostname === "google.com" || hostname.endsWith(".google.com")) && parsedUrl.pathname === "/search") ||
      (hostname === "www.bing.com" && parsedUrl.pathname.startsWith("/search")) ||
      ((hostname === "duckduckgo.com" || hostname === "www.duckduckgo.com") && (parsedUrl.pathname === "/" || parsedUrl.pathname.startsWith("/html"))) ||
      ((hostname === "search.yahoo.com" || hostname === "www.yahoo.com") && parsedUrl.pathname.includes("search"))
    ) {
      return "search";
    }
  } catch (error) {
    return "page";
  }

  return "page";
}

function dedupeLinks(links) {
  const seen = new Set();
  return links.filter((link) => {
    const href = normalizeHref(link.href);
    if (!href || seen.has(href)) {
      return false;
    }
    seen.add(href);
    link.href = href;
    return true;
  });
}

function normalizeHref(href) {
  try {
    const url = new URL(href);
    url.hash = "";
    return url.href;
  } catch (error) {
    return "";
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
  const visualCloneSignals = latestResult?.signals?.visual_clone_signals?.length
    ? latestResult.signals.visual_clone_signals.join("\n- ")
    : "None";
  const trustSignals = latestResult?.trust_signals?.length
    ? latestResult.trust_signals.join("\n- ")
    : "None";
  const threatIntelSignals = latestResult?.threat_intel?.is_known_bad
    ? latestResult.threat_intel.reason || "URL matched configured local threat intelligence."
    : "None";
  const deepUrlSignals = latestResult?.deep_analysis?.signals?.length
    ? latestResult.deep_analysis.signals
        .map((signal) => (typeof signal === "string" ? signal : signal.message))
        .join("\n- ")
    : "None";
  const attackExplanation = latestResult?.attack_explanation;
  const attackAvoid = attackExplanation?.what_to_avoid?.length
    ? attackExplanation.what_to_avoid.join("\n- ")
    : "None";

  return `TrustTrace AI Scan Report
Scan Type: ${latestScanType}
URL: ${latestResult?.url || currentTabUrl}
Risk Level: ${latestResult?.risk_level || "Unavailable"}
Trust Score: ${latestResult?.trust_score ?? "Unavailable"}
Phishing Probability: ${Math.round((latestResult?.phishing_probability || 0) * 100)}%
Detection Confidence: ${latestResult?.confidence || "N/A"}
Repeat Count: ${latestResult?.repeat_count || "N/A"}
Attack Type: ${attackExplanation?.attack_type || "N/A"}
Attack Summary: ${attackExplanation?.summary || "N/A"}
What To Avoid:
- ${attackAvoid}
Safer Action: ${attackExplanation?.safer_action || "N/A"}
Visual Clone Score: ${latestResult?.visual_clone?.visual_clone_score ?? "N/A"}
Visual Clone Confidence: ${latestResult?.visual_clone?.visual_clone_confidence || "N/A"}
Reasons:
- ${reasons}
Trust Signals:
- ${trustSignals}
Threat Intelligence:
- ${threatIntelSignals}
Deep URL Signals:
- ${deepUrlSignals}
Visual Clone Signals:
- ${visualCloneSignals}
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
scanLinksButton.addEventListener("click", scanLinksOnPage);
clipboardToggleElement.addEventListener("change", () => {
  setClipboardGuardianEnabled(clipboardToggleElement.checked);
});
scanClipboardButton.addEventListener("click", scanClipboardNow);
refreshReportButton.addEventListener("click", renderSecurityReport);
resetReportButton.addEventListener("click", resetLocalSecurityReport);

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
initializeClipboardGuardianControls();
renderSecurityReport();

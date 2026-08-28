(() => {
  "use strict";

const MAX_VISIBLE_TEXT_LENGTH = 5000;
const SEARCH_BADGE_ATTRIBUTE = "data-trusttrace-search-badge";
const SEARCH_RESULT_ATTRIBUTE = "data-trusttrace-search-scanned";
const SEARCH_BADGE_CLASS = "trusttrace-result-badge";
const SEARCH_BADGE_WRAP_CLASS = "trusttrace-badge-row";
const MAX_SEARCH_RESULTS_TO_SCAN = 15;
const DEFAULT_VISIBLE_LINK_LIMIT = 25;
const PAGE_LINK_SCAN_LIMIT = 30;
const CLIPBOARD_GUARDIAN_SETTING_KEY = "trusttraceClipboardGuardianEnabled";
const OFFICIAL_GITHUB_DOMAINS = [
  "github.com",
  "githubstatus.com"
];
const TRUSTTRACE_BRAND_TERMS = [
  "apple",
  "apple id",
  "icloud",
  "google",
  "gmail",
  "youtube",
  "openai",
  "chatgpt",
  "claude",
  "anthropic",
  "microsoft",
  "outlook",
  "office",
  "paypal",
  "amazon",
  "netflix",
  "facebook",
  "instagram",
  "github",
  "chase",
  "bank of america",
  "wells fargo",
  "dhl",
  "fedex",
  "usps"
];
const searchResultCache = new Map();
let searchScanTimer = null;
let clipboardGuardianEnabled = false;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "SHOW_CAUTION_BANNER") {
    showCautionBanner(message.result);
    sendResponse({ ok: true });
    return false;
  }

  if (message?.type === "TRUSTTRACE_EXTRACT_VISIBLE_LINKS") {
    const mode = message.mode || "page";
    sendResponse({
      links: extractVisibleLinks({ mode }),
      page_url: window.location.href,
      page_title: document.title || "",
      mode
    });
    return false;
  }

  if (message?.type !== "TRUSTTRACE_COLLECT_PAGE") {
    return false;
  }

  sendResponse({
    pageTitle: document.title || "",
    selectedText: getSelectedText().slice(0, MAX_VISIBLE_TEXT_LENGTH),
    visibleText: getVisibleBodyText().slice(0, MAX_VISIBLE_TEXT_LENGTH),
    forms: collectFormMetadata(),
    links: collectVisibleLinks(),
    visualMetadata: collectVisualMetadata(),
    clipboardSignals: clipboardGuardianEnabled
      ? TrustTraceClipboardGuardian.detectSensitiveClipboardPageSignals(document)
      : [],
    messageCandidates: collectMessageCandidates()
  });

  return true;
});

initSearchResultBadges();
initClipboardGuardianContent();

function getVisibleBodyText() {
  const bodyText = document.body?.innerText || "";
  return bodyText.replace(/\s+/g, " ").trim();
}

function getSelectedText() {
  return window.getSelection()?.toString().replace(/\s+/g, " ").trim() || "";
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

function collectVisibleLinks() {
  return extractVisibleLinks({ mode: "message", maxLinks: 30 }).map((link) => ({
    text: link.text,
    href: link.href
  }));
}

function collectVisualMetadata() {
  const images = Array.from(document.images || [])
    .filter(isVisible)
    .slice(0, 30)
    .map((image) => buildImageMetadata(image));
  const logoCandidates = images
    .filter((image) => isLogoCandidateMetadata(image))
    .slice(0, 10);

  return {
    document_title: document.title || "",
    primary_headings: Array.from(document.querySelectorAll("h1, h2, h3"))
      .filter(isVisible)
      .map((heading) => cleanText(heading.innerText || heading.textContent || ""))
      .filter(Boolean)
      .slice(0, 20),
    favicons: collectFaviconMetadata(),
    images,
    logo_candidates: logoCandidates,
    button_texts: collectButtonTexts(),
    input_labels: collectInputLabels(),
    brand_like_text: collectBrandLikeText(),
    color_hints: collectColorHints(),
    layout_hints: collectLayoutHints()
  };
}

function collectFaviconMetadata() {
  return Array.from(document.querySelectorAll("link[rel*='icon' i], link[rel='apple-touch-icon' i]"))
    .slice(0, 10)
    .map((link) => ({
      href: link.href || link.getAttribute("href") || "",
      type: link.getAttribute("type") || "",
      rel: link.getAttribute("rel") || ""
    }));
}

function buildImageMetadata(image) {
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
}

function isLogoCandidateMetadata(image) {
  const combined = `${image.src} ${image.alt} ${image.title} ${image.class_name} ${image.id} ${image.nearby_text}`.toLowerCase();
  const logoLikeSize = image.width >= 24 && image.height >= 24 && image.width <= 260 && image.height <= 180;
  return (
    combined.includes("logo") ||
    TRUSTTRACE_BRAND_TERMS.some((term) => combined.includes(term)) ||
    (logoLikeSize && image.nearby_text && TRUSTTRACE_BRAND_TERMS.some((term) => image.nearby_text.toLowerCase().includes(term)))
  );
}

function collectButtonTexts() {
  return Array.from(document.querySelectorAll("button, input[type='submit'], input[type='button'], a[role='button']"))
    .filter(isVisible)
    .map((button) => cleanText(button.innerText || button.value || button.getAttribute("aria-label") || ""))
    .filter(Boolean)
    .slice(0, 40);
}

function collectInputLabels() {
  return Array.from(document.querySelectorAll("input, textarea, select"))
    .filter(isVisible)
    .map((input) => {
      const explicitLabel = input.id ? document.querySelector(`label[for="${cssEscape(input.id)}"]`) : null;
      const wrapperLabel = input.closest("label");
      return cleanText([
        explicitLabel?.innerText || "",
        wrapperLabel?.innerText || "",
        input.getAttribute("placeholder") || "",
        input.getAttribute("aria-label") || "",
        input.getAttribute("name") || "",
        input.id || ""
      ].join(" "));
    })
    .filter(Boolean)
    .slice(0, 40);
}

function collectBrandLikeText() {
  const pageText = cleanText([
    document.title || "",
    Array.from(document.querySelectorAll("h1, h2, h3, [aria-label], [title]"))
      .filter(isVisible)
      .map((element) => `${element.innerText || ""} ${element.getAttribute("aria-label") || ""} ${element.getAttribute("title") || ""}`)
      .join(" "),
    (document.body?.innerText || "").slice(0, 2500)
  ].join(" "));

  return TRUSTTRACE_BRAND_TERMS
    .filter((term) => pageText.toLowerCase().includes(term))
    .slice(0, 20);
}

function collectColorHints() {
  const bodyStyle = window.getComputedStyle(document.body || document.documentElement);
  return [
    bodyStyle.backgroundColor || "",
    bodyStyle.color || ""
  ].filter(Boolean).slice(0, 4);
}

function collectLayoutHints() {
  const passwordInput = document.querySelector("input[type='password']");
  const emailInput = Array.from(document.querySelectorAll("input")).find(isEmailOrUsernameInput);
  const forms = Array.from(document.forms).filter(isVisible);
  const loginContainer = passwordInput?.closest("form, main, section, article, div") || null;
  const rect = loginContainer?.getBoundingClientRect?.();
  const viewportCenterX = window.innerWidth / 2;
  const hasCenteredLoginCard = Boolean(
    rect &&
    passwordInput &&
    rect.width > 220 &&
    rect.width < Math.min(window.innerWidth, 620) &&
    Math.abs((rect.left + rect.width / 2) - viewportCenterX) < window.innerWidth * 0.22
  );
  const bodyTextLength = cleanText(document.body?.innerText || "").length;
  const visibleInputs = Array.from(document.querySelectorAll("input")).filter(isVisible);

  return {
    has_centered_login_card: hasCenteredLoginCard,
    has_fullscreen_login_layout: Boolean(passwordInput && emailInput && forms.length <= 2 && bodyTextLength < 4000),
    has_minimal_login_page: Boolean(passwordInput && visibleInputs.length <= 8 && bodyTextLength < 2200)
  };
}

function getNearbyText(element, maxLength) {
  const container = element.closest("header, main, section, article, form, div") || element.parentElement || element;
  return cleanText(container.innerText || container.textContent || "").slice(0, maxLength);
}

function cleanText(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function collectMessageCandidates() {
  const selectedText = getSelectedText();
  const elements = getCandidateElements();

  return elements
    .map((element, index) => buildMessageCandidate(element, index, selectedText))
    .filter((candidate) => candidate.message_text.length >= 20)
    .sort((a, b) => b.confidence_score - a.confidence_score || a.position.top - b.position.top)
    .slice(0, 12);
}

async function initClipboardGuardianContent() {
  try {
    const stored = await chrome.storage.local.get(CLIPBOARD_GUARDIAN_SETTING_KEY);
    clipboardGuardianEnabled = Boolean(stored[CLIPBOARD_GUARDIAN_SETTING_KEY]);
  } catch (error) {
    clipboardGuardianEnabled = false;
  }

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local" && changes[CLIPBOARD_GUARDIAN_SETTING_KEY]) {
      clipboardGuardianEnabled = Boolean(changes[CLIPBOARD_GUARDIAN_SETTING_KEY].newValue);
    }
  });

  document.addEventListener("click", handleClipboardCopyClick, true);
}

function handleClipboardCopyClick(event) {
  if (!clipboardGuardianEnabled) {
    return;
  }

  const element = event.target?.closest?.("button, a, [role='button'], [data-clipboard-text], [data-copy]");
  if (!element || !looksLikeCopyElement(element)) {
    return;
  }

  const copiedValue = getDeclaredCopiedValue(element);
  if (!copiedValue) {
    return;
  }

  const visibleValue = getNearbyVisibleCopyValue(element);
  const comparison = TrustTraceClipboardGuardian.compareVisibleAndCopiedValue(visibleValue, copiedValue);

  if (comparison.mismatch) {
    showClipboardGuardianToast(comparison.reason);
    chrome.runtime.sendMessage({ type: "TRUSTTRACE_RECORD_CLIPBOARD_MISMATCH" });
  }
}

function looksLikeCopyElement(element) {
  const text = `${element.innerText || ""} ${element.getAttribute("aria-label") || ""} ${element.getAttribute("title") || ""}`.toLowerCase();
  return Boolean(
    element.hasAttribute("data-clipboard-text") ||
    element.hasAttribute("data-copy") ||
    text.includes("copy")
  );
}

function getDeclaredCopiedValue(element) {
  return (
    element.getAttribute("data-clipboard-text") ||
    element.getAttribute("data-copy") ||
    element.getAttribute("data-copy-value") ||
    ""
  ).trim();
}

function getNearbyVisibleCopyValue(element) {
  const container = element.closest("section, article, li, p, div") || element.parentElement || element;
  return (container.innerText || "").replace(/\s+/g, " ").trim();
}

function showClipboardGuardianToast(message) {
  const existingToast = document.getElementById("trusttrace-clipboard-toast");
  if (existingToast) {
    existingToast.remove();
  }

  const toast = document.createElement("div");
  toast.id = "trusttrace-clipboard-toast";
  toast.style.cssText = [
    "position:fixed",
    "right:16px",
    "bottom:16px",
    "z-index:2147483647",
    "max-width:340px",
    "padding:12px 14px",
    "border:1px solid #f59e0b",
    "border-radius:12px",
    "background:#fffbeb",
    "color:#422006",
    "box-shadow:0 14px 34px rgba(0,0,0,0.22)",
    "font:600 13px/1.4 Arial,sans-serif"
  ].join(";");
  toast.textContent = `TrustTrace Clipboard Guardian: ${message}`;
  document.documentElement.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 6200);
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
  const elements = Array.from(document.querySelectorAll(selectors.join(",")));
  const uniqueElements = [];

  elements.forEach((element) => {
    if (!isVisible(element) || uniqueElements.some((existing) => existing.contains(element))) {
      return;
    }
    uniqueElements.push(element);
  });

  return uniqueElements;
}

function buildMessageCandidate(element, index, selectedText) {
  const rect = element.getBoundingClientRect();
  const messageText = (element.innerText || "").replace(/\s+/g, " ").trim();
  const links = Array.from(element.querySelectorAll("a[href]")).map((link) => ({
    text: link.innerText.replace(/\s+/g, " ").trim(),
    href: link.href
  }));
  const sender = extractSender(element, messageText);
  const subject = extractSubject(element, messageText);
  const confidenceScore = scoreCandidate(element, messageText, links, sender, subject);

  return {
    candidate_id: `message-${index + 1}`,
    sender,
    subject,
    preview: messageText.slice(0, 300),
    message_text: messageText.slice(0, MAX_VISIBLE_TEXT_LENGTH),
    links,
    source_url: window.location.href,
    confidence_score: selectedText && messageText.includes(selectedText) ? confidenceScore + 50 : confidenceScore,
    contains_selection: Boolean(selectedText && messageText.includes(selectedText)),
    position: {
      top: Math.max(0, Math.round(rect.top + window.scrollY)),
      left: Math.max(0, Math.round(rect.left + window.scrollX)),
      width: Math.round(rect.width),
      height: Math.round(rect.height)
    }
  };
}

function extractSender(element, text) {
  const explicitSender = element.getAttribute("data-sender");
  if (explicitSender) {
    return explicitSender.trim();
  }

  const senderMatch = text.match(/\b(?:sender|from):\s*([^\n]+?)(?:\s{2,}| subject:| message:|$)/i);
  return senderMatch ? senderMatch[1].trim() : "";
}

function extractSubject(element, text) {
  const explicitSubject = element.getAttribute("data-subject");
  if (explicitSubject) {
    return explicitSubject.trim();
  }

  const heading = element.querySelector("h1, h2, h3, [data-subject]");
  if (heading?.innerText) {
    return heading.innerText.trim();
  }

  const subjectMatch = text.match(/\bsubject:\s*([^\n]+?)(?:\s{2,}| sender:| from:| message:|$)/i);
  return subjectMatch ? subjectMatch[1].trim() : document.title || "";
}

function scoreCandidate(element, text, links, sender, subject) {
  let score = 0;
  const lowerText = text.toLowerCase();

  if (element.matches(".trusttrace-message-card, [data-trusttrace-message]")) score += 50;
  if (element.matches("[data-sender], [data-subject], article, [role='article']")) score += 25;
  if (sender) score += 15;
  if (subject) score += 10;
  if (links.length > 0) score += 10;
  if (/(urgent|suspended|locked|verify|password|security code|payment failed)/.test(lowerText)) score += 20;

  return score;
}

function isVisible(element) {
  const rect = element.getBoundingClientRect();
  const style = window.getComputedStyle(element);
  return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
}

function showCautionBanner(result) {
  const existingBanner = document.getElementById("trusttrace-caution-banner");
  if (existingBanner) {
    existingBanner.remove();
  }

  const banner = document.createElement("div");
  banner.id = "trusttrace-caution-banner";
  banner.style.cssText = [
    "position: fixed",
    "top: 0",
    "left: 0",
    "right: 0",
    "z-index: 2147483647",
    "padding: 12px 16px",
    "background: #fef3c7",
    "color: #422006",
    "border-bottom: 2px solid #f59e0b",
    "box-shadow: 0 8px 24px rgba(0,0,0,0.18)",
    "font-family: Arial, sans-serif",
    "font-size: 14px",
    "line-height: 1.4"
  ].join(";");

  const reasons = (result?.reasons || []).slice(0, 2);
  const probability = Math.round((Number(result?.phishing_probability) || 0) * 100);
  const visualIssue = result?.visual_clone?.visual_clone_confidence === "medium"
    ? "Visual brand mismatch detected."
    : "";
  const possibleIssue = visualIssue || result?.attack_explanation?.attack_type;

  banner.innerHTML = `
    <div style="display:flex; gap:12px; align-items:flex-start; justify-content:space-between;">
      <div>
        <strong>TrustTrace AI caution: this page has some suspicious signals.</strong>
        <div>Trust score: ${result?.trust_score ?? "N/A"} · Phishing probability: ${probability}%</div>
        ${possibleIssue ? `<div>Possible issue: ${escapeHtml(possibleIssue)}</div>` : ""}
        ${reasons.length ? `<ul style="margin:6px 0 0; padding-left:18px;">${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>` : ""}
      </div>
      <div style="display:flex; gap:8px; flex:0 0 auto;">
        <button id="trusttrace-open-popup" style="padding:7px 10px; border:1px solid #92400e; border-radius:8px; background:#fffbeb; color:#422006; cursor:pointer;">Open TrustTrace AI</button>
        <button id="trusttrace-dismiss-caution" style="padding:7px 10px; border:1px solid #92400e; border-radius:8px; background:#92400e; color:#fff; cursor:pointer;">Dismiss</button>
      </div>
    </div>
  `;

  document.documentElement.appendChild(banner);
  document.getElementById("trusttrace-dismiss-caution")?.addEventListener("click", () => {
    banner.remove();
  });
  document.getElementById("trusttrace-open-popup")?.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "TRUSTTRACE_OPEN_POPUP" });
  });
}

function initSearchResultBadges() {
  if (!isSearchResultsPage()) {
    return;
  }

  if (!document.body) {
    window.addEventListener("DOMContentLoaded", initSearchResultBadges, { once: true });
    return;
  }

  scanVisibleSearchResults();

  const observer = new MutationObserver(() => {
    window.clearTimeout(searchScanTimer);
    searchScanTimer = window.setTimeout(scanVisibleSearchResults, 500);
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

function scanVisibleSearchResults() {
  const results = extractVisibleLinks({
    mode: "search",
    maxLinks: MAX_SEARCH_RESULTS_TO_SCAN
  }).map((result) => ({
    link: document.querySelector(`[data-trusttrace-link-id="${cssEscape(result.id)}"]`),
    targetUrl: result.href
  })).filter((result) => result.link);

  results.forEach(({ link, targetUrl }) => {
    if (link.getAttribute(SEARCH_RESULT_ATTRIBUTE) === targetUrl && hasSearchResultBadge(link, targetUrl)) {
      return;
    }

    link.setAttribute(SEARCH_RESULT_ATTRIBUTE, targetUrl);
    const badge = attachSearchResultBadge(link, targetUrl);
    updateSearchBadge(badge, {
      label: "TrustTrace: Unknown",
      level: "pending",
      title: "TrustTrace AI is checking this result URL."
    });

    analyzeSearchResult(targetUrl)
      .then((result) => {
        updateSearchBadgeFromResult(badge, targetUrl, result);
      })
      .catch(() => {
        updateSearchBadge(badge, {
          label: "TrustTrace: Unknown",
          level: "offline",
          title: "TrustTrace AI local analysis is unavailable."
        });
      });
  });
}

function extractVisibleLinks(options = {}) {
  const mode = options.mode || "page";
  const maxLinks = options.maxLinks || getLinkLimit(mode);
  const seenUrls = new Set();
  const candidates = getVisibleLinkCandidates(mode);

  return candidates
    .map((link) => buildVisibleLinkRecord(link, mode))
    .filter((record) => {
      if (!record || seenUrls.has(record.href)) {
        return false;
      }
      seenUrls.add(record.href);
      return true;
    })
    .slice(0, maxLinks);
}

function getLinkLimit(mode) {
  if (mode === "search") {
    return MAX_SEARCH_RESULTS_TO_SCAN;
  }
  if (mode === "page") {
    return PAGE_LINK_SCAN_LIMIT;
  }
  return DEFAULT_VISIBLE_LINK_LIMIT;
}

function getVisibleLinkCandidates(mode) {
  if (mode === "search" || isSearchResultsPage()) {
    return getSearchResultLinkCandidates();
  }

  return Array.from(document.querySelectorAll("a[href]"))
    .filter((link) => isAllowedVisibleLink(link) && !isLikelyNavigationOrClutter(link));
}

function getSearchResultLinkCandidates() {
  const engine = getSearchEngine();
  const selectorsByEngine = {
    google: "#search a[href]",
    bing: "#b_results .b_algo h2 a[href], #b_results .b_title a[href]",
    duckduckgo: "article a[href], [data-testid='result-title-a'][href], .result__title a[href]",
    yahoo: "#web a[href], .algo a[href]"
  };
  const selector = selectorsByEngine[engine] || "a[href]";

  return Array.from(document.querySelectorAll(selector))
    .filter((link) => isAllowedVisibleLink(link) && isSearchResultLink(link, extractSearchResultUrl(link)));
}

function buildVisibleLinkRecord(link, mode) {
  const href = extractSearchResultUrl(link);
  if (!href || !isAllowedHref(href)) {
    return null;
  }

  try {
    const url = new URL(href);
    const id = buildLinkId(href);
    link.setAttribute("data-trusttrace-link-id", id);

    return {
      id,
      href: url.href,
      text: getLinkText(link).slice(0, 160),
      hostname: url.hostname,
      context: getSurroundingContext(link).slice(0, 150),
      is_search_result: mode === "search" || isSearchResultLink(link, href),
      is_message_link: isInsideMessageLikeArea(link)
    };
  } catch (error) {
    return null;
  }
}

function extractSearchResultUrl(link) {
  try {
    const rawHref = link.getAttribute("href") || link.href || "";
    const hrefUrl = new URL(rawHref, window.location.href);
    if (isGoogleRedirectUrl(hrefUrl)) {
      const redirectedUrl = getRedirectDestination(hrefUrl);
      if (redirectedUrl) {
        return new URL(redirectedUrl, window.location.href).href;
      }
    }
    return hrefUrl.href;
  } catch (error) {
    return "";
  }
}

function isGoogleRedirectUrl(url) {
  return (
    (url.hostname === "google.com" || url.hostname.endsWith(".google.com")) &&
    ["/url", "/aclk", "/imgres", "/interstitial"].includes(url.pathname)
  );
}

function getRedirectDestination(url) {
  const redirectParams = ["url", "q", "adurl", "imgurl", "imgrefurl"];
  for (const param of redirectParams) {
    const value = url.searchParams.get(param);
    if (value && /^https?:\/\//i.test(value)) {
      return value;
    }
  }
  return "";
}

function isSearchResultLink(link, targetUrl) {
  try {
    const target = new URL(targetUrl);
    const engine = getSearchEngine();
    const hasResultTitle = Boolean(
      link.querySelector("h3") ||
      link.closest("[data-sokoban-container]")?.querySelector("h3") ||
      link.closest(".b_algo") ||
      link.closest("article") ||
      link.closest(".algo")
    );
    const isWebUrl = ["http:", "https:"].includes(target.protocol);
    const isSearchEngineUtility = isSearchEngineHostname(target.hostname) && !isLikelyOfficialSearchResult(link, engine);

    return hasResultTitle && isWebUrl && !isSearchEngineUtility && isVisible(link);
  } catch (error) {
    return false;
  }
}

function attachSearchResultBadge(link, targetUrl) {
  injectSearchBadgeStyles();

  const insertionTarget = getSearchBadgeInsertionTarget(link);
  const existingBadge = insertionTarget.parentElement?.querySelector(
    `.${SEARCH_BADGE_WRAP_CLASS}[data-trusttrace-url="${cssEscape(targetUrl)}"] .${SEARCH_BADGE_CLASS}`
  );
  if (existingBadge) {
    return existingBadge;
  }

  const wrapper = document.createElement("div");
  wrapper.className = SEARCH_BADGE_WRAP_CLASS;
  wrapper.setAttribute("data-trusttrace-url", targetUrl);

  const badge = document.createElement("span");
  badge.className = SEARCH_BADGE_CLASS;
  badge.setAttribute(SEARCH_BADGE_ATTRIBUTE, "true");
  badge.setAttribute("role", "status");

  wrapper.appendChild(badge);
  insertionTarget.insertAdjacentElement("afterend", wrapper);
  return badge;
}

function hasSearchResultBadge(link, targetUrl) {
  const insertionTarget = getSearchBadgeInsertionTarget(link);
  return Boolean(
    insertionTarget.parentElement?.querySelector(
      `.${SEARCH_BADGE_WRAP_CLASS}[data-trusttrace-url="${cssEscape(targetUrl)}"] .${SEARCH_BADGE_CLASS}`
    )
  );
}

function injectSearchBadgeStyles() {
  if (document.getElementById("trusttrace-search-badge-styles")) {
    return;
  }

  const style = document.createElement("style");
  style.id = "trusttrace-search-badge-styles";
  style.textContent = `
    .${SEARCH_BADGE_WRAP_CLASS},
    .${SEARCH_BADGE_WRAP_CLASS} * {
      all: initial !important;
      box-sizing: border-box !important;
      font-family: Arial, sans-serif !important;
      direction: ltr !important;
      unicode-bidi: isolate !important;
      writing-mode: horizontal-tb !important;
      text-orientation: mixed !important;
      transform: none !important;
    }

    .${SEARCH_BADGE_WRAP_CLASS} {
      display: block !important;
      margin: 6px 0 4px 0 !important;
      padding: 0 !important;
      width: max-content !important;
      max-width: 100% !important;
      position: static !important;
      float: none !important;
      clear: both !important;
      background: transparent !important;
    }

    .${SEARCH_BADGE_CLASS} {
      display: inline-flex !important;
      align-items: center !important;
      justify-content: center !important;
      white-space: nowrap !important;
      direction: ltr !important;
      unicode-bidi: isolate !important;
      writing-mode: horizontal-tb !important;
      transform: none !important;
      rotate: none !important;
      scale: none !important;
      font-size: 12px !important;
      font-weight: 700 !important;
      line-height: 1 !important;
      padding: 5px 10px !important;
      border-radius: 999px !important;
      border: 1px solid rgba(148, 163, 184, 0.55) !important;
      box-shadow: 0 2px 8px rgba(15, 23, 42, 0.12) !important;
      cursor: default !important;
      user-select: none !important;
    }
  `;
  document.documentElement.appendChild(style);
}

function getSearchBadgeInsertionTarget(link) {
  if (getSearchEngine() !== "google") {
    return link.querySelector("h3")?.closest("a") || link;
  }

  const titleAnchor = (link.querySelector("h3") ? link : link.closest("a")) || link;
  const titleContainer = titleAnchor.closest(".yuRUbf") || titleAnchor.parentElement || titleAnchor;
  const resultContainer = titleAnchor.closest(".MjjYud, .g, [data-sokoban-container]") || titleContainer;

  return findStableBadgeInsertionTarget(titleContainer, resultContainer);
}

function isUnsafeGoogleBadgeContainer(element) {
  return Boolean(
    element?.closest("svg, cite, g-menu, [role='menu'], [aria-haspopup], .VuuXrf, .qLRx3b")
  );
}

function findStableBadgeInsertionTarget(preferredTarget, resultContainer) {
  let insertionTarget = preferredTarget;
  let current = preferredTarget;

  while (current && current !== document.body) {
    if (isUnsafeGoogleBadgeContainer(current) || hasTransformOrVerticalText(current)) {
      insertionTarget = current;
    }
    if (current === resultContainer) {
      break;
    }
    current = current.parentElement;
  }

  return insertionTarget;
}

function hasTransformOrVerticalText(element) {
  const style = window.getComputedStyle(element);
  return (
    style.transform !== "none" ||
    style.rotate !== "none" ||
    style.scale !== "none" ||
    style.writingMode !== "horizontal-tb" ||
    style.direction !== "ltr"
  );
}

function resetSearchBadgeOrientation(badge) {
  badge.style.display = "inline-flex";
  badge.style.alignItems = "center";
  badge.style.justifyContent = "center";
  badge.style.writingMode = "horizontal-tb";
  badge.style.direction = "ltr";
  badge.style.unicodeBidi = "isolate";
  badge.style.textOrientation = "mixed";
  badge.style.transform = "none";
  badge.style.rotate = "none";
  badge.style.scale = "none";
  badge.style.whiteSpace = "nowrap";
  badge.style.fontSize = "12px";
  badge.style.lineHeight = "1";
}

async function analyzeSearchResult(targetUrl) {
  if (searchResultCache.has(targetUrl)) {
    return searchResultCache.get(targetUrl);
  }

  try {
    const response = await chrome.runtime.sendMessage({
      type: "TRUSTTRACE_ANALYZE_SEARCH_RESULT",
      url: targetUrl
    });

    if (response?.ok) {
      searchResultCache.set(targetUrl, response.result);
      return response.result;
    }
  } catch (error) {
    // Fall through to browser-local analysis below.
  }

  if (globalThis.TrustTraceLocalAnalyzer?.analyzeUrl) {
    const result = globalThis.TrustTraceLocalAnalyzer.analyzeUrl(targetUrl);
    searchResultCache.set(targetUrl, result);
    return result;
  }

  throw new Error("Search result analysis failed.");
}

function updateSearchBadgeFromResult(badge, targetUrl, result) {
  const displayResult = isOfficialGitHubUrl(targetUrl) ? buildOfficialGitHubBadgeResult(result) : result;
  const level = getSearchBadgeLevel(displayResult);
  const labels = {
    trusted: `TrustTrace: Trusted ${displayResult?.trust_score ?? ""}`,
    low: `TrustTrace: Low Risk ${displayResult?.trust_score ?? ""}`,
    caution: `TrustTrace: Caution ${displayResult?.trust_score ?? ""}`,
    high: `TrustTrace: High Risk ${displayResult?.trust_score ?? ""}`
  };

  updateSearchBadge(badge, {
    label: labels[level],
    level,
    title: buildSearchBadgeTitle(displayResult)
  });

  if (level === "high") {
    badge.setAttribute("role", "button");
    badge.setAttribute("tabindex", "0");
    badge.style.setProperty("cursor", "pointer", "important");
    badge.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      chrome.runtime.sendMessage({
        type: "TRUSTTRACE_OPEN_WARNING_FOR_URL",
        url: targetUrl,
        result: displayResult
      });
    });
  }
}

function isOfficialGitHubUrl(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return OFFICIAL_GITHUB_DOMAINS.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
  } catch (error) {
    return false;
  }
}

function buildOfficialGitHubBadgeResult(result = {}) {
  const trustScore = Math.max(Number(result?.trust_score || 0), 95);
  return {
    ...result,
    risk_level: "low",
    trust_score: trustScore,
    phishing_probability: Math.min(Number(result?.phishing_probability ?? 0.05), 0.05),
    confidence: "high",
    reasons: [],
    trust_signals: [
      "Official GitHub domain detected.",
      ...(result?.trust_signals || [])
    ]
  };
}


function getSearchBadgeLevel(result) {
  return classifyLinkRisk(result).level;
}

function classifyLinkRisk(result) {
  const trustScore = Number(result?.trust_score);
  const probability = Number(result?.phishing_probability);

  if (
    trustScore <= 30 ||
    probability >= 0.75 ||
    (result?.risk_level === "high" && result?.confidence === "high")
  ) {
    return { level: "high", label: "High Risk" };
  }

  if ((trustScore > 30 && trustScore <= 60) || result?.risk_level === "medium") {
    return { level: "caution", label: "Caution" };
  }

  if (trustScore >= 80) {
    return { level: "trusted", label: "Trusted" };
  }

  return { level: "low", label: "Low" };
}

function updateSearchBadge(badge, state) {
  const styles = {
    pending: {
      text: "#334155",
      background: "#f8fafc",
      border: "rgba(148,163,184,0.65)"
    },
    trusted: {
      text: "#065f46",
      background: "#d1fae5",
      border: "#34d399"
    },
    low: {
      text: "#0f766e",
      background: "#ccfbf1",
      border: "#5eead4"
    },
    caution: {
      text: "#78350f",
      background: "#fef3c7",
      border: "#f59e0b"
    },
    high: {
      text: "#7f1d1d",
      background: "#fee2e2",
      border: "#ef4444"
    },
    offline: {
      text: "#475569",
      background: "#e2e8f0",
      border: "#94a3b8"
    }
  };
  const style = styles[state.level] || styles.pending;

  badge.textContent = state.label;
  badge.title = state.title;
  resetSearchBadgeOrientation(badge);
  badge.style.setProperty("color", style.text, "important");
  badge.style.setProperty("background", style.background, "important");
  badge.style.setProperty("border-color", style.border, "important");
}

function buildSearchBadgeTitle(result) {
  const topReasons = (result?.reasons || []).slice(0, 2).join(" ");
  const attackType = result?.attack_explanation?.attack_type;
  if (attackType && topReasons) {
    return `${attackType}: ${topReasons}`;
  }
  if (attackType) {
    return `${attackType}: ${result?.attack_explanation?.summary || "TrustTrace found a possible issue."}`;
  }
  return topReasons || `TrustTrace AI: ${result?.risk_level || "low"} risk, trust score ${result?.trust_score ?? "N/A"}.`;
}

function isSearchResultsPage() {
  return Boolean(getSearchEngine());
}

function getSearchEngine() {
  const hostname = location.hostname.toLowerCase();
  const path = location.pathname;

  if ((hostname === "google.com" || hostname.endsWith(".google.com")) && path === "/search") {
    return "google";
  }
  if (hostname === "www.bing.com" && path.startsWith("/search")) {
    return "bing";
  }
  if ((hostname === "duckduckgo.com" || hostname === "www.duckduckgo.com") && (path === "/" || path.startsWith("/html"))) {
    return "duckduckgo";
  }
  if ((hostname === "search.yahoo.com" || hostname === "www.yahoo.com") && path.includes("search")) {
    return "yahoo";
  }

  return "";
}

function isSearchEngineHostname(hostname) {
  return (
    hostname.endsWith("google.com") ||
    hostname.endsWith("bing.com") ||
    hostname.endsWith("duckduckgo.com") ||
    hostname.endsWith("yahoo.com")
  );
}

function isLikelyOfficialSearchResult(link, engine) {
  if (engine === "google") {
    return Boolean(link.querySelector("h3"));
  }
  return Boolean(link.closest(".b_algo, article, .algo"));
}

function isAllowedVisibleLink(link) {
  const href = extractSearchResultUrl(link);
  return Boolean(href && isAllowedHref(href) && isVisible(link) && getLinkText(link));
}

function isAllowedHref(href) {
  try {
    const url = new URL(href, window.location.href);
    if (!["http:", "https:"].includes(url.protocol)) {
      return false;
    }
    if (url.href.split("#")[0] === window.location.href.split("#")[0] && url.hash) {
      return false;
    }
    return true;
  } catch (error) {
    return false;
  }
}

function isLikelyNavigationOrClutter(link) {
  const container = link.closest("nav, header, footer, aside, [role='navigation']");
  const text = getLinkText(link).toLowerCase();
  const href = link.href.toLowerCase();
  const rect = link.getBoundingClientRect();
  const isTinyIcon = rect.width < 32 && rect.height < 32 && text.length < 3;
  const looksLikeShare = /(share|facebook|twitter|x\.com|linkedin|pinterest|reddit|mailto)/.test(`${text} ${href}`);

  return Boolean(container || isTinyIcon || looksLikeShare);
}

function getLinkText(link) {
  return (link.innerText || link.textContent || link.getAttribute("aria-label") || link.href || "")
    .replace(/\s+/g, " ")
    .trim();
}

function getSurroundingContext(link) {
  const container = link.closest("article, section, li, p, div, [role='article'], .trusttrace-message-card") || link;
  return (container.innerText || getLinkText(link)).replace(/\s+/g, " ").trim();
}

function isInsideMessageLikeArea(link) {
  return Boolean(
    link.closest(".trusttrace-message-card, [data-trusttrace-message], [data-sender], [data-subject], article, [role='article'], .message, .email, .mail, .conversation, .chat-message")
  );
}

function buildLinkId(href) {
  let hash = 0;
  for (let index = 0; index < href.length; index += 1) {
    hash = ((hash << 5) - hash + href.charCodeAt(index)) | 0;
  }
  return `trusttrace-link-${Math.abs(hash)}`;
}

function cssEscape(value) {
  if (window.CSS?.escape) {
    return window.CSS.escape(value);
  }
  return String(value).replaceAll("\"", "\\\"");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}

})();

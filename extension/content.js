const MAX_VISIBLE_TEXT_LENGTH = 5000;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "TRUSTTRACE_COLLECT_PAGE") {
    return false;
  }

  sendResponse({
    pageTitle: document.title || "",
    selectedText: getSelectedText().slice(0, MAX_VISIBLE_TEXT_LENGTH),
    visibleText: getVisibleBodyText().slice(0, MAX_VISIBLE_TEXT_LENGTH),
    forms: collectFormMetadata(),
    links: collectVisibleLinks(),
    messageCandidates: collectMessageCandidates()
  });

  return true;
});

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
  return Array.from(document.querySelectorAll("a[href]"))
    .filter((link) => link.innerText.trim() || link.href)
    .slice(0, 30)
    .map((link) => ({
      text: link.innerText.replace(/\s+/g, " ").trim(),
      href: link.href
    }));
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

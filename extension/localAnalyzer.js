(() => {
  "use strict";

const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "account", "secure", "update", "bank", "password",
  "refund", "payment", "billing", "signin", "signup", "sign-in", "sign-up"
];
const CREDENTIAL_CONTEXT = [
  "login", "sign in", "signin", "verify", "account", "password", "payment",
  "billing", "bank", "security", "secure", "update", "recovery", "otp", "code"
];
const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".click", ".work", ".zip", ".country", ".stream", ".gq",
  ".tk", ".ml", ".ga", ".cf", ".loan", ".party", ".download", ".gdn"
];
const URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"];
const LOCAL_BLOCKLIST_URLS = [
  "http://apple-login-security.example.com/verify",
  "https://openai-login-verify.example.com/password",
  "https://claude-security-login.example.com",
  "https://gemini-google-verify-account.xyz/login",
  "http://github-login-security.example.com/verify",
  "https://github-security-verify.xyz/login",
  "https://githhub-login.example.com"
];
const LOCAL_BLOCKLIST_DOMAINS = [
  "apple-login-security.example.com",
  "openai-login-verify.example.com",
  "claude-security-login.example.com",
  "gemini-google-verify-account.xyz",
  "github-login-security.example.com",
  "github-security-verify.xyz",
  "githhub-login.example.com"
];
const TRUSTED_BRANDS = {
  apple: ["apple.com"],
  google: ["google.com", "youtube.com"],
  gemini: ["google.com"],
  youtube: ["youtube.com", "google.com"],
  openai: ["openai.com", "chatgpt.com"],
  chatgpt: ["chatgpt.com", "openai.com"],
  anthropic: ["anthropic.com"],
  claude: ["claude.ai", "anthropic.com"],
  microsoft: ["microsoft.com", "live.com", "office.com"],
  amazon: ["amazon.com"],
  paypal: ["paypal.com"],
  netflix: ["netflix.com"],
  facebook: ["facebook.com"],
  instagram: ["instagram.com"],
  chase: ["chase.com"],
  bankofamerica: ["bankofamerica.com"],
  wellsfargo: ["wellsfargo.com"],
  usps: ["usps.com"],
  dhl: ["dhl.com"],
  fedex: ["fedex.com"],
  github: ["github.com", "githubstatus.com"],
  wikipedia: ["wikipedia.org"]
};
const HIGH_REPUTATION_DOMAINS = [
  "apple.com", "www.apple.com", "support.apple.com", "google.com", "www.google.com",
  "youtube.com", "www.youtube.com", "gemini.google.com", "openai.com", "chatgpt.com",
  "claude.ai", "anthropic.com", "microsoft.com", "amazon.com", "github.com",
  "www.github.com", "gist.github.com", "docs.github.com", "support.github.com",
  "githubstatus.com", "www.githubstatus.com", "wikipedia.org", "verizon.com",
  "www.verizon.com", "bestbuy.com", "www.bestbuy.com", "walmart.com", "www.walmart.com",
  "target.com", "www.target.com", "costco.com", "www.costco.com", "att.com",
  "www.att.com", "t-mobile.com", "www.t-mobile.com"
];
const TRUSTED_COMMERCE_DOMAINS = [
  "verizon.com", "bestbuy.com", "walmart.com", "target.com", "amazon.com",
  "costco.com", "att.com", "t-mobile.com"
];
const PRODUCT_CONTEXT = [
  "shop", "store", "product", "products", "iphone", "watch", "phone", "phones",
  "cart", "price", "deal", "trade-in", "reviews", "listing", "delivery", "pickup",
  "buy", "sale", "search", "desktop", "apps", "download", "docs"
];
const FREE_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com", "proton.me", "aol.com"];
const MESSAGE_CATEGORIES = [
  { key: "urgency", terms: ["urgent", "immediately", "act now", "final warning", "limited time", "respond now"], message: "The message uses urgency or pressure language." },
  { key: "account_threat", terms: ["suspended", "locked", "disabled", "restricted", "unusual activity", "account closure", "account will be closed"], message: "The message uses account-threat language." },
  { key: "credential", terms: ["password", "login", "verify", "confirm identity", "security code", "authentication code", "one-time code", "otp"], message: "The message asks for login, password, or security-code verification." },
  { key: "payment", terms: ["refund", "payment failed", "invoice", "billing", "bank account", "card declined", "transaction failed"], message: "The message references payment, invoice, refund, or banking issues." },
  { key: "prize", terms: ["congratulations", "winner", "claim reward", "free gift", "lottery", "prize"], message: "The message uses prize or giveaway language commonly seen in scams." },
  { key: "fear", terms: ["unauthorized access", "security alert", "suspicious activity", "account compromised"], message: "The message uses fear or security-alert language." }
];

function analyzeUrl(input) {
  const url = typeof input === "string" ? input : input?.url;
  const parsed = parseUrl(url);
  if (!parsed) {
    return lowResult(url || "", ["Unsupported or invalid URL for local analysis."], [], "low");
  }

  const hostname = parsed.hostname.toLowerCase();
  const normalizedUrl = parsed.href;
  const reputation = analyzeReputation(parsed);
  const threatIntel = localThreatIntel(normalizedUrl, hostname);
  const reasons = [];
  const trustSignals = [...reputation.trust_signals];
  const urlSignals = [];
  const deepSignals = [];
  let points = 0;

  if (threatIntel.is_known_bad) {
    reasons.push(threatIntel.reason);
    points = 100;
  } else if (reputation.is_official_brand_domain && reputation.matched_brand === "github") {
    return trustedOfficialResult(normalizedUrl, reputation, "Official GitHub domain detected.");
  } else if (reputation.is_official_brand_domain || reputation.is_high_reputation_domain) {
    points = parsed.protocol === "http:" ? 20 : 3;
    if (parsed.protocol === "http:") {
      reasons.push("The page uses HTTP instead of encrypted HTTPS.");
    }
  } else {
    const keywordHits = SUSPICIOUS_KEYWORDS.filter((term) => normalizedUrl.toLowerCase().includes(term));
    const hasCredentialContext = containsAny(normalizedUrl.toLowerCase(), CREDENTIAL_CONTEXT);
    const suspiciousTld = SUSPICIOUS_TLDS.find((tld) => hostname.endsWith(tld));
    const hyphenCount = (hostname.match(/-/g) || []).length;
    const subdomainCount = Math.max(hostname.split(".").filter(Boolean).length - 2, 0);

    if (parsed.protocol === "http:") addSignal("The page uses HTTP instead of encrypted HTTPS.", 25);
    if (keywordHits.length) addSignal(`The URL contains phishing-related keyword(s): ${keywordHits.slice(0, 5).join(", ")}.`, 18);
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) addSignal("The URL uses an IP address instead of a normal domain name.", 25);
    if (hyphenCount >= 3) addSignal("The domain contains excessive hyphens, which can be used to imitate trusted domains.", 18);
    if (subdomainCount >= 3) addSignal("The URL contains many subdomains, which can mimic trusted sites.", 15);
    if (normalizedUrl.includes("@")) addSignal("The URL contains an @ symbol, which can hide the real destination.", 25);
    if (URL_SHORTENERS.includes(hostname.replace(/^www\./, ""))) addSignal("The URL uses a known link shortener, which can hide the final destination.", 35);
    if (suspiciousTld) addSignal(`The URL uses a suspicious top-level domain (${suspiciousTld}).`, hasCredentialContext ? 75 : 30);
    if (/%[0-9a-f]{2}/i.test(normalizedUrl)) addSignal("The URL contains encoded characters that can obscure its destination.", 10);
    if (parsed.search.length > 80) addSignal("The URL has an unusually long query string.", 10);
    if (reputation.reputation_warnings.length) {
      reasons.push(...reputation.reputation_warnings);
      urlSignals.push(...reputation.reputation_warnings);
      points = Math.max(points, hasCredentialContext ? 85 : 60);
      deepSignals.push(...reputation.reputation_warnings.map((message) => ({ type: "brand_spoofing", severity: "high", message })));
    }

    const lookalike = detectLookalike(hostname);
    if (lookalike) {
      reasons.push(lookalike);
      urlSignals.push(lookalike);
      deepSignals.push({ type: "typosquatting", severity: "high", message: lookalike });
      points = Math.max(points, hasCredentialContext ? 75 : 45);
    }
  }

  function addSignal(message, score) {
    reasons.push(message);
    urlSignals.push(message);
    points = Math.max(points, score);
  }

  return buildRiskResult({
    url: normalizedUrl,
    points,
    reasons,
    trustSignals,
    reputation,
    threatIntel,
    signals: { url_signals: dedupe(urlSignals), content_signals: [], form_signals: [], visual_clone_signals: [] },
    deepSignals
  });
}

function analyzePage(payload = {}) {
  const urlResult = analyzeUrl(payload.url || "");
  const content = analyzeText(payload.visible_text || payload.page_title || "", "page");
  const forms = analyzeForms(payload.forms || [], payload.url || "", content.score, urlResult);
  const visualClone = analyzeVisualClone(payload, forms, urlResult);
  const clipboardSignals = payload.clipboard_signals || [];
  let points = Math.max(
    riskPoints(urlResult),
    Math.round(riskPoints(urlResult) * 0.45 + content.score * 0.3 + forms.score * 0.25),
    visualClone.score >= 70 ? 85 : visualClone.score >= 40 ? 55 : 0,
    clipboardSignals.length ? 35 : 0
  );
  const reasons = dedupe([
    ...(urlResult.reasons || []),
    ...content.reasons,
    ...forms.reasons,
    ...visualClone.reasons,
    ...clipboardSignals
  ]);
  const signals = {
    url_signals: urlResult.signals?.url_signals || [],
    content_signals: content.reasons,
    form_signals: forms.reasons,
    visual_clone_signals: visualClone.reasons,
    clipboard_signals: clipboardSignals
  };

  if (forms.hasHttpPasswordForm) {
    points = 90;
  }
  if ((urlResult.reputation?.is_official_brand_domain || urlResult.reputation?.is_high_reputation_domain) && visualClone.score < 40 && forms.score < 70) {
    points = Math.min(points, 15);
  }

  return buildRiskResult({
    url: payload.url || "",
    points,
    reasons,
    trustSignals: [...(urlResult.trust_signals || []), ...visualClone.trustSignals],
    reputation: urlResult.reputation,
    threatIntel: urlResult.threat_intel,
    signals,
    visualClone: visualClone.summary
  });
}

function analyzeMessage(payload = {}) {
  const text = `${payload.subject || ""} ${payload.message_text || ""}`.toLowerCase();
  const message = analyzeText(text, "message");
  const sender = analyzeSender(payload.sender || "", payload.sender_type || "unknown", text);
  const linkResults = (payload.links || []).slice(0, 20).map((link) => analyzeMessageLink(link, text));
  const linkScore = Math.max(0, ...linkResults.map((item) => item.score));
  const points = Math.max(
    Math.round(message.score * 0.35 + sender.score * 0.25 + linkScore * 0.3),
    sender.score >= 75 && message.score >= 45 ? 85 : 0,
    linkScore >= 75 && message.score >= 35 ? 80 : 0
  );
  const reasons = dedupe([...sender.reasons, ...message.reasons, ...linkResults.flatMap((item) => item.reasons)]);
  const result = buildRiskResult({
    url: payload.source_url || "",
    points,
    reasons,
    trustSignals: [],
    reputation: {},
    threatIntel: { is_known_bad: false, source: "browser_local", reason: "" },
    signals: {
      sender_signals: sender.reasons,
      message_signals: message.reasons,
      link_signals: linkResults.flatMap((item) => item.reasons),
      repeat_signals: []
    }
  });
  return {
    ...result,
    repeat_count: 1,
    repeat_warning: null
  };
}

function analyzeReputation(parsed) {
  const hostname = parsed.hostname.toLowerCase();
  const urlText = `${hostname} ${parsed.pathname} ${parsed.search}`.toLowerCase();
  const trustSignals = [];
  const warnings = [];
  let matchedBrand = "";
  let officialDomain = "";
  let isOfficial = false;

  for (const [brand, domains] of Object.entries(TRUSTED_BRANDS)) {
    const official = domains.find((domain) => isDomainOrSubdomain(hostname, domain));
    if (official) {
      matchedBrand = brand;
      officialDomain = official;
      isOfficial = true;
      trustSignals.push(`Official ${formatBrand(brand)} domain detected.`);
      break;
    }
    if (!matchedBrand && brandAppears(urlText, brand)) {
      matchedBrand = brand;
      officialDomain = domains[0];
      if (isTrustedCommerce(hostname) && containsAny(urlText, PRODUCT_CONTEXT) && !containsAny(urlText, CREDENTIAL_CONTEXT)) {
        trustSignals.push(`Trusted commerce domain detected; ${formatBrand(brand)} appears in product listing context.`);
      } else if (hasSuspiciousBrandContext(hostname, urlText, brand)) {
        warnings.push(`${formatBrand(brand)} brand keyword appears outside the official ${domains[0]} domain in a login/security context.`);
      }
    }
  }

  const isHighReputation = HIGH_REPUTATION_DOMAINS.includes(hostname);
  if (isHighReputation) {
    trustSignals.push("Domain is in the local high-reputation list.");
  }

  return {
    hostname,
    is_official_brand_domain: isOfficial,
    matched_brand: matchedBrand,
    official_domain: officialDomain,
    is_high_reputation_domain: isHighReputation,
    reputation_score: isOfficial && isHighReputation ? 95 : isOfficial ? 85 : isHighReputation ? 90 : warnings.length ? 20 : 50,
    trust_signals: dedupe(trustSignals),
    reputation_warnings: warnings
  };
}

function analyzeText(text, source) {
  const normalized = String(text || "").toLowerCase();
  const reasons = [];
  let score = 0;
  MESSAGE_CATEGORIES.forEach((category) => {
    if (containsAny(normalized, category.terms)) {
      reasons.push(source === "page" ? category.message.replace("message", "page") : category.message);
      score += category.key === "credential" || category.key === "account_threat" ? 22 : 15;
    }
  });
  if (containsAny(normalized, ["urgent", "immediately", "suspended", "locked"]) && containsAny(normalized, ["password", "verify", "security code", "otp"])) {
    reasons.push("Urgent account or credential-verification language appears together.");
    score += 30;
  }
  return { score: Math.min(score, 100), reasons: dedupe(reasons) };
}

function analyzeForms(forms, pageUrl, contentScore, urlResult) {
  const parsed = parseUrl(pageUrl);
  const reasons = [];
  let score = 0;
  let hasHttpPasswordForm = false;
  forms.forEach((form, index) => {
    const label = `Form ${index + 1}`;
    const submitText = String(form.submit_text || "").toLowerCase();
    if (form.has_password_field) {
      reasons.push(`${label}: A password field was detected.`);
      score += 28;
      if (parsed?.protocol === "http:") {
        reasons.push("Password or credential entry was detected on an unencrypted HTTP page.");
        hasHttpPasswordForm = true;
        score += 70;
      }
    }
    if (form.has_email_or_username_field && form.has_password_field) {
      reasons.push(`${label}: The form asks for both an email or username and a password.`);
      score += 25;
    }
    if (!form.action) {
      reasons.push(`${label}: The form action is missing, which can make destination behavior unclear.`);
      score += 12;
    } else if (parsed) {
      const action = parseUrl(form.action, parsed.href);
      if (action && action.hostname && action.hostname !== parsed.hostname) {
        reasons.push(`${label}: The login form submits data to a different domain than the current page.`);
        score += 35;
      }
      if (action?.protocol === "http:") {
        reasons.push(`${label}: The form submits over HTTP instead of encrypted HTTPS.`);
        score += 35;
      }
    }
    if (/(verify|confirm|update|unlock|secure|continue)/.test(submitText)) {
      reasons.push(`${label}: The submit button uses verification or account-security wording.`);
      score += 18;
    }
    if (Number(form.hidden_input_count || 0) >= 3 && !(urlResult.reputation?.is_official_brand_domain || urlResult.reputation?.is_high_reputation_domain)) {
      reasons.push(`${label}: The form contains several hidden inputs.`);
      score += 10;
    }
    if (form.has_password_field && contentScore >= 45) {
      reasons.push(`${label}: A password field was detected on a page with suspicious account-verification or security-alert language.`);
      score += 35;
    }
  });
  return { score: Math.min(score, 100), reasons: dedupe(reasons), hasHttpPasswordForm };
}

function analyzeVisualClone(payload, formAnalysis, urlResult) {
  const metadata = payload.visual_metadata || {};
  const text = [
    payload.page_title, payload.visible_text, metadata.document_title,
    ...(metadata.primary_headings || []), ...(metadata.button_texts || []),
    ...(metadata.input_labels || []), ...(metadata.brand_like_text || []),
    ...(metadata.logo_candidates || []).map((item) => `${item.alt || ""} ${item.title || ""} ${item.src || ""}`)
  ].join(" ").toLowerCase();
  const claimedBrands = Object.keys(TRUSTED_BRANDS).filter((brand) => brandAppears(text, brand));
  const official = urlResult.reputation?.is_official_brand_domain;
  const reasons = [];
  const trustSignals = [];
  let score = 0;

  if (official && claimedBrands.length) {
    trustSignals.push("Official brand domain matched visual brand claim.");
  } else if (claimedBrands.length && formAnalysis.score >= 35) {
    const brand = formatBrand(claimedBrands[0]);
    reasons.push(`Page visually claims to represent ${brand}.`);
    reasons.push(`Page claims to represent ${brand}, but the domain is not an official ${brand} domain.`);
    reasons.push("A branded login form appears on a non-official domain.");
    score = 85;
  }

  return {
    score,
    reasons,
    trustSignals,
    summary: {
      is_visual_clone_suspected: score >= 70,
      visual_clone_score: score,
      visual_clone_confidence: score >= 70 ? "high" : score >= 40 ? "medium" : "low",
      primary_clone_brand: claimedBrands[0] || null,
      claimed_brands: claimedBrands,
      signals: reasons.map((message) => ({ type: "visual_clone_signal", severity: score >= 70 ? "high" : "medium", brand: formatBrand(claimedBrands[0] || ""), message }))
    }
  };
}

function analyzeSender(sender, senderType, messageText) {
  const normalizedSender = String(sender || "").toLowerCase().trim();
  const reasons = [];
  let score = 0;
  const mentionedBrands = Object.keys(TRUSTED_BRANDS).filter((brand) => brandAppears(messageText, brand));
  const domain = normalizedSender.includes("@") ? normalizedSender.split("@").pop() : "";
  if (senderType === "phone" && (mentionedBrands.length || containsAny(messageText, ["bank", "company", "security"]))) {
    reasons.push("The message claims to be from a company or bank but appears to come from a regular phone number.");
    score += 45;
  }
  if (domain && FREE_EMAIL_DOMAINS.includes(domain) && mentionedBrands.length) {
    reasons.push(`The sender uses a personal/free email provider while claiming to represent ${formatBrand(mentionedBrands[0])}.`);
    score += 75;
  }
  mentionedBrands.forEach((brand) => {
    if (domain && !TRUSTED_BRANDS[brand].some((official) => isDomainOrSubdomain(domain, official))) {
      reasons.push(`The message mentions ${formatBrand(brand)}, but the sender domain does not match the official ${formatBrand(brand)} domain.`);
      score += 45;
    }
  });
  return { score: Math.min(score, 100), reasons: dedupe(reasons) };
}

function analyzeMessageLink(link, messageText) {
  const result = analyzeUrl(link.href || "");
  const reasons = [...(result.reasons || [])];
  let score = riskPoints(result);
  const linkText = String(link.text || "").toLowerCase();
  Object.keys(TRUSTED_BRANDS).forEach((brand) => {
    if (brandAppears(`${linkText} ${messageText}`, brand)) {
      const destination = parseUrl(link.href || "");
      const official = destination && TRUSTED_BRANDS[brand].some((domain) => isDomainOrSubdomain(destination.hostname, domain));
      if (!official) {
        reasons.push(`The displayed link text mentions ${formatBrand(brand)}, but the actual destination is not ${TRUSTED_BRANDS[brand][0]}.`);
        score = Math.max(score, 80);
      }
    }
  });
  return { score, reasons: dedupe(reasons) };
}

function buildRiskResult({ url, points, reasons, trustSignals, reputation, threatIntel, signals, visualClone = null, deepSignals = [] }) {
  const finalPoints = clamp(Math.round(points || 0), 0, 100);
  const riskLevel = finalPoints >= 70 ? "high" : finalPoints >= 30 ? "medium" : "low";
  return {
    url,
    risk_level: riskLevel,
    phishing_probability: Number((finalPoints / 100).toFixed(2)),
    trust_score: 100 - finalPoints,
    reasons: dedupe(reasons || []),
    confidence: finalPoints >= 70 || finalPoints <= 10 ? "high" : "medium",
    trust_signals: dedupe(trustSignals || []),
    reputation: normalizeReputation(reputation),
    threat_intel: threatIntel || { is_known_bad: false, source: "browser_local", reason: "" },
    deep_analysis: { signals: deepSignals, score_delta: deepSignals.length ? Math.max(...deepSignals.map((signal) => signal.score_delta || 0)) : 0 },
    signals: signals || {},
    visual_clone: visualClone,
    attack_explanation: buildAttackExplanation(riskLevel, reasons || [], visualClone)
  };
}

function trustedOfficialResult(url, reputation, signal) {
  return buildRiskResult({
    url,
    points: 5,
    reasons: [],
    trustSignals: dedupe([signal, ...(reputation.trust_signals || [])]),
    reputation,
    threatIntel: { is_known_bad: false, source: "browser_local", reason: "" },
    signals: { url_signals: [], content_signals: [], form_signals: [], visual_clone_signals: [] }
  });
}

function lowResult(url, reasons, trustSignals, confidence) {
  const result = buildRiskResult({
    url,
    points: 0,
    reasons,
    trustSignals,
    reputation: {},
    threatIntel: { is_known_bad: false, source: "browser_local", reason: "" },
    signals: { url_signals: [], content_signals: [], form_signals: [], visual_clone_signals: [] }
  });
  result.confidence = confidence;
  return result;
}

function buildAttackExplanation(riskLevel, reasons, visualClone) {
  const evidence = reasons.join(" ").toLowerCase();
  let attackType = "No strong attack pattern identified";
  if (/known-bad|blocklist/.test(evidence)) attackType = "Malware or known-bad URL";
  else if (visualClone?.is_visual_clone_suspected) attackType = "Visual brand cloning / fake login page";
  else if (/password|credential|security code|otp|verify/.test(evidence)) attackType = "Credential phishing";
  else if (/brand keyword|official .* domain|displayed link text/.test(evidence)) attackType = "Brand impersonation phishing";
  else if (/typosquat|lookalike|similar to/.test(evidence)) attackType = "Typosquatting / lookalike domain";
  else if (/shortener|hide the final destination/.test(evidence)) attackType = "Suspicious link redirection";
  else if (/urgent|pressure|suspended|locked/.test(evidence)) attackType = "Urgency / social engineering pressure";

  return {
    attack_type: attackType,
    attack_category: riskLevel === "low" ? "Low-risk" : "Browser-local threat analysis",
    severity: riskLevel,
    summary: attackType === "No strong attack pattern identified"
      ? "No strong attack pattern was identified by the browser-local checks."
      : `${attackType} indicators were found by browser-local checks.`,
    how_it_works: attackType === "No strong attack pattern identified"
      ? ["TrustTrace checked local URL, page, form, message, and reputation signals where available."]
      : reasons.slice(0, 3),
    what_to_avoid: riskLevel === "low"
      ? ["Stay alert for unusual requests for passwords, payment details, or security codes."]
      : ["Do not enter passwords, OTPs, recovery phrases, payment details, or personal information on suspicious pages."],
    safer_action: riskLevel === "low"
      ? "Continue normally, while staying alert for unusual prompts."
      : "Go directly to the official website by typing the address yourself or using a trusted bookmark."
  };
}

function localThreatIntel(url, hostname) {
  if (LOCAL_BLOCKLIST_URLS.includes(url)) {
    return { is_known_bad: true, source: "browser_local_blocklist", reason: "URL matched local MVP known-bad blocklist." };
  }
  if (LOCAL_BLOCKLIST_DOMAINS.includes(hostname)) {
    return { is_known_bad: true, source: "browser_local_domain_blocklist", reason: "Domain matched local MVP known-bad blocklist." };
  }
  return { is_known_bad: false, source: "browser_local", reason: "" };
}

function detectLookalike(hostname) {
  const labels = hostname.split(".").flatMap((label) => [label, ...label.split("-"), label.replace(/-/g, "")]);
  for (const brand of Object.keys(TRUSTED_BRANDS)) {
    for (const label of labels) {
      const normalized = label.replaceAll("0", "o").replaceAll("1", "l");
      if (normalized !== brand && levenshtein(normalized, brand) <= 2 && normalized.length >= 5) {
        return `The hostname is very similar to the trusted brand ${formatBrand(brand)}.`;
      }
    }
  }
  return "";
}

function hasSuspiciousBrandContext(hostname, urlText, brand) {
  const compactHostname = hostname.replace(/[-_]/g, "");
  const brandInHost = compactHostname.includes(brand.replace(/[-_ ]/g, ""));
  return containsAny(urlText, CREDENTIAL_CONTEXT) || (brandInHost && (hostname.includes("-") || containsAny(hostname, CREDENTIAL_CONTEXT)));
}

function brandAppears(text, brand) {
  return String(text || "").replace(/[-_\s]/g, "").includes(brand.replace(/[-_\s]/g, ""));
}

function isTrustedCommerce(hostname) {
  return TRUSTED_COMMERCE_DOMAINS.some((domain) => isDomainOrSubdomain(hostname, domain));
}

function isDomainOrSubdomain(hostname, domain) {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

function containsAny(text, terms) {
  return terms.some((term) => text.includes(term));
}

function parseUrl(url, base) {
  try {
    return new URL(url, base);
  } catch (error) {
    return null;
  }
}

function riskPoints(result) {
  return Math.round(Number(result?.phishing_probability || 0) * 100);
}

function normalizeReputation(reputation = {}) {
  return {
    is_official_brand_domain: Boolean(reputation.is_official_brand_domain),
    is_high_reputation_domain: Boolean(reputation.is_high_reputation_domain),
    matched_brand: reputation.matched_brand || "",
    reputation_score: Number(reputation.reputation_score || 0)
  };
}

function formatBrand(brand) {
  const names = { openai: "OpenAI", chatgpt: "ChatGPT", github: "GitHub", usps: "USPS", dhl: "DHL", fedex: "FedEx", bankofamerica: "Bank of America", wellsfargo: "Wells Fargo" };
  return names[brand] || `${brand.charAt(0).toUpperCase()}${brand.slice(1)}`;
}

function dedupe(values) {
  return [...new Set((values || []).filter(Boolean))];
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j += 1) dp[0][j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[a.length][b.length];
}

globalThis.TrustTraceLocalAnalyzer = {
  analyzeUrl,
  analyzePage,
  analyzeMessage
};

})();

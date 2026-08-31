(() => {
  "use strict";

const CLIPBOARD_SUSPICIOUS_TLDS = [
  ".xyz",
  ".top",
  ".click",
  ".work",
  ".zip",
  ".tk",
  ".ml",
  ".gq"
];

const CLIPBOARD_SENSITIVE_PAGE_TERMS = [
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

function analyzeClipboardText(text, urlAnalysisResult = null) {
  const normalizedText = String(text || "").trim();
  const signals = [];

  const suspiciousUrl = detectSuspiciousUrl(normalizedText, urlAnalysisResult);
  const otp = detectOtpOrSecurityCode(normalizedText);
  const wallet = detectWalletAddress(normalizedText);
  const recovery = detectRecoveryPhrase(normalizedText);
  const credential = detectCredentialLikeText(normalizedText);

  [suspiciousUrl, otp, wallet, recovery, credential].forEach((result) => {
    if (result.detected) {
      signals.push(...result.signals);
    }
  });

  return classifyClipboardRisk(signals);
}

function detectSuspiciousUrl(text, urlAnalysisResult = null) {
  if (!/^https?:\/\//i.test(text)) {
    return { detected: false, signals: [] };
  }

  const signals = [];
  if (urlAnalysisResult) {
    if (urlAnalysisResult.risk_level === "high" || Number(urlAnalysisResult.trust_score) <= 30) {
      signals.push({
        type: "Suspicious URL",
        severity: "high",
        message: "Clipboard URL was rated high risk by TrustTrace URL analysis."
      });
    } else if (urlAnalysisResult.risk_level === "medium") {
      signals.push({
        type: "Suspicious URL",
        severity: "medium",
        message: "Clipboard URL was rated caution by TrustTrace URL analysis."
      });
    }
    return { detected: signals.length > 0, signals };
  }

  try {
    const url = new URL(text);
    const lowerUrl = url.href.toLowerCase();
    const hostname = url.hostname.toLowerCase();

    if (url.protocol === "http:") {
      signals.push({
        type: "Suspicious URL",
        severity: "medium",
        message: "Clipboard contains an HTTP URL instead of encrypted HTTPS."
      });
    }
    if (CLIPBOARD_SUSPICIOUS_TLDS.some((tld) => hostname.endsWith(tld))) {
      signals.push({
        type: "Suspicious URL",
        severity: "medium",
        message: "Clipboard URL uses a suspicious top-level domain."
      });
    }
    if (/(login|verify|account|update|security|password|billing|payment)/i.test(lowerUrl)) {
      signals.push({
        type: "Suspicious URL",
        severity: "medium",
        message: "Clipboard URL contains login, account, payment, or verification wording."
      });
    }
  } catch (error) {
    signals.push({
      type: "Suspicious URL",
      severity: "medium",
      message: "Clipboard appears to contain a URL-like value that could not be parsed cleanly."
    });
  }

  if (signals.length === 0) {
    signals.push({
      type: "Suspicious URL",
      severity: "low",
      message: "Clipboard contains a URL. Verify the destination before pasting it into sensitive pages."
    });
  }

  return { detected: true, signals };
}

function detectWalletAddress(text) {
  const normalizedText = String(text || "").trim();
  const isEthereum = /^0x[a-fA-F0-9]{40}$/.test(normalizedText);
  const isBitcoin = /^(bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(normalizedText);

  if (!isEthereum && !isBitcoin) {
    return { detected: false, signals: [] };
  }

  return {
    detected: true,
    signals: [{
      type: "Possible wallet address",
      severity: "medium",
      message: "Clipboard contains a possible wallet address. Check wallet addresses carefully before sending funds."
    }]
  };
}

function detectOtpOrSecurityCode(text) {
  const normalizedText = String(text || "").trim();
  const hasCodeContext = /(otp|security code|verification code|one-time code|authentication code)/i.test(normalizedText);
  const isShortNumericCode = /^\d{4,8}$/.test(normalizedText);
  const hasInlineCode = /\b\d{4,8}\b/.test(normalizedText) && hasCodeContext;

  if (!isShortNumericCode && !hasInlineCode) {
    return { detected: false, signals: [] };
  }

  return {
    detected: true,
    signals: [{
      type: "Possible OTP/security code",
      severity: "medium",
      message: "This looks like a verification code. Only paste it into the official site or app."
    }]
  };
}

function detectRecoveryPhrase(text) {
  const normalizedText = String(text || "").trim();
  const words = normalizedText.split(/\s+/).filter(Boolean);
  const hasRecoveryContext = /(seed phrase|recovery phrase|private key|wallet recovery)/i.test(normalizedText);
  const phraseLengthLooksSensitive = [12, 18, 24].includes(words.length);

  if (!hasRecoveryContext && !phraseLengthLooksSensitive) {
    return { detected: false, signals: [] };
  }

  return {
    detected: true,
    signals: [{
      type: "Possible recovery phrase/seed phrase",
      severity: "high",
      message: "Never paste a recovery phrase or private key into a website."
    }]
  };
}

function detectCredentialLikeText(text) {
  if (!/(password=|pwd\b|token\b|api_key|secret\b|bearer\s+)/i.test(text)) {
    return { detected: false, signals: [] };
  }

  return {
    detected: true,
    signals: [{
      type: "Sensitive credential-like content",
      severity: "high",
      message: "Clipboard may contain credential-like information such as a password, token, secret, or API key."
    }]
  };
}

function detectSensitiveClipboardPageSignals(documentRef = document) {
  const bodyText = (documentRef.body?.innerText || "").replace(/\s+/g, " ").toLowerCase();
  const signals = [];

  CLIPBOARD_SENSITIVE_PAGE_TERMS.forEach((term) => {
    if (bodyText.includes(term)) {
      signals.push(`Page contains clipboard-sensitive language: ${term}.`);
    }
  });

  return Array.from(new Set(signals)).slice(0, 8);
}

function compareVisibleAndCopiedValue(visible, copied) {
  const normalizedVisible = normalizeComparableValue(visible);
  const normalizedCopied = normalizeComparableValue(copied);

  if (!normalizedVisible || !normalizedCopied || normalizedVisible === normalizedCopied) {
    return {
      mismatch: false,
      reason: ""
    };
  }

  const visibleSensitive = extractSensitiveComparableValue(normalizedVisible);
  const copiedSensitive = extractSensitiveComparableValue(normalizedCopied);

  if (visibleSensitive && copiedSensitive && visibleSensitive !== copiedSensitive) {
    return {
      mismatch: true,
      reason: "The copied value appears different from the visible value shown on the page. This may indicate clipboard manipulation."
    };
  }

  return {
    mismatch: false,
    reason: ""
  };
}

function classifyClipboardRisk(signals) {
  const highestSeverity = signals.some((signal) => signal.severity === "high")
    ? "high"
    : signals.some((signal) => signal.severity === "medium")
      ? "medium"
      : "low";
  const detectedType = signals[0]?.type || "No obvious clipboard threat";

  return {
    risk_level: highestSeverity,
    detected_type: detectedType,
    reasons: signals.length
      ? signals.map((signal) => signal.message)
      : ["No obvious clipboard threat was detected by local checks."],
    safer_action: saferActionForClipboard(highestSeverity, detectedType),
    signals
  };
}

function saferActionForClipboard(riskLevel, detectedType) {
  if (/recovery|seed|credential/i.test(detectedType) || riskLevel === "high") {
    return "Do not paste recovery phrases, private keys, passwords, OTPs, or payment addresses into untrusted pages.";
  }
  if (/wallet/i.test(detectedType)) {
    return "Verify wallet addresses manually before sending funds.";
  }
  if (/url/i.test(detectedType)) {
    return "Open sensitive sites from trusted bookmarks or by typing the official address yourself.";
  }
  if (/otp|security code/i.test(detectedType)) {
    return "Only paste verification codes into the official site or app where you requested the code.";
  }
  return "Review clipboard content before pasting it into sensitive pages.";
}

function normalizeComparableValue(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function extractSensitiveComparableValue(value) {
  const url = value.match(/https?:\/\/[^\s"'<>]+/i)?.[0];
  if (url) return url;
  const ethereum = value.match(/0x[a-fA-F0-9]{40}/)?.[0];
  if (ethereum) return ethereum;
  const bitcoin = value.match(/\b(bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/)?.[0];
  if (bitcoin) return bitcoin;
  const code = value.match(/\b\d{4,8}\b/)?.[0];
  return code || "";
}

globalThis.TrustTraceClipboardGuardian = {
  analyzeClipboardText,
  detectSuspiciousUrl,
  detectWalletAddress,
  detectOtpOrSecurityCode,
  detectRecoveryPhrase,
  detectCredentialLikeText,
  detectSensitiveClipboardPageSignals,
  compareVisibleAndCopiedValue,
  classifyClipboardRisk
};

})();

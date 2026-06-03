const TRUSTTRACE_DEMO_SCENARIOS = [
  {
    id: "trusted-official",
    title: "Trusted Official Website",
    scenario_label: "Official domain reputation",
    url: "https://www.apple.com",
    risk_level: "low",
    trust_score: 98,
    phishing_probability: 0.02,
    attack_type: "No strong attack pattern identified",
    summary: "TrustTrace recognizes the official Apple domain and suppresses weak false-positive signals.",
    signals: [
      "Official Apple domain detected.",
      "Domain is in the local high-reputation list.",
      "No strong phishing indicators found."
    ],
    what_to_avoid: [],
    safer_action: "Continue normally, while staying alert for unusual prompts."
  },
  {
    id: "fake-phishing-url",
    title: "Fake Phishing URL",
    scenario_label: "Pre-visit warning eligible",
    url: "http://apple-login-security.example.com/verify",
    risk_level: "high",
    trust_score: 0,
    phishing_probability: 1.0,
    attack_type: "Known-bad URL / malware",
    summary: "A fake Apple login/security URL matches the local MVP blocklist and would trigger the high-risk warning page.",
    signals: [
      "URL matched local MVP known-bad blocklist.",
      "The URL uses HTTP instead of encrypted HTTPS.",
      "The domain combines a trusted brand with security/login wording."
    ],
    what_to_avoid: [
      "Do not enter passwords or security codes.",
      "Do not download files from this destination."
    ],
    safer_action: "Close the page and go directly to the official Apple website."
  },
  {
    id: "visual-clone",
    title: "Visual Clone / Fake Login Page",
    scenario_label: "Visual Clone Intelligence",
    url: "http://127.0.0.1:5500/extension/test-visual-clone.html",
    risk_level: "high",
    trust_score: 0,
    phishing_probability: 1.0,
    attack_type: "Visual brand cloning / fake login page",
    summary: "The page claims trusted brands, shows branded login patterns, and asks for credentials on a non-official domain.",
    signals: [
      "Page visually claims to represent Apple.",
      "A branded login form appears on a non-official domain.",
      "Brand-related security or verification language appears on a non-official domain."
    ],
    what_to_avoid: [
      "Do not trust logos alone.",
      "Do not enter passwords, OTPs, recovery codes, or payment details."
    ],
    safer_action: "Check the domain carefully and use a trusted bookmark for the real service."
  },
  {
    id: "message-threat",
    title: "Suspicious Email / Message",
    scenario_label: "Sender identity + message language",
    url: "https://mail.google.com/",
    risk_level: "high",
    trust_score: 5,
    phishing_probability: 0.95,
    attack_type: "Credential phishing",
    summary: "A free Gmail sender claims to represent Google and uses urgent password verification language.",
    signals: [
      "The sender uses a personal/free email provider while claiming to represent Google.",
      "The message uses account-suspension language.",
      "The message asks for password or security-code verification."
    ],
    what_to_avoid: [
      "Do not click account recovery links from the message.",
      "Do not share passwords or security codes."
    ],
    safer_action: "Open the official Google account page directly and check security status there."
  },
  {
    id: "clipboard-risk",
    title: "Clipboard Guardian Risk",
    scenario_label: "Clipboard manipulation",
    url: "http://127.0.0.1:5500/extension/test-clipboard-guardian.html",
    risk_level: "high",
    trust_score: 10,
    phishing_probability: 0.9,
    attack_type: "Clipboard manipulation risk",
    summary: "A copy button can show one wallet address while copying a different value, or a page may ask for recovery phrases.",
    signals: [
      "The copied value appears different from the visible value shown on the page.",
      "Page contains recovery phrase/private key language.",
      "Clipboard contains a suspicious URL."
    ],
    what_to_avoid: [
      "Do not paste recovery phrases, private keys, passwords, OTPs, or payment addresses into untrusted pages.",
      "Verify wallet addresses manually before sending funds."
    ],
    safer_action: "Use official apps or trusted websites and manually verify sensitive copied values."
  },
  {
    id: "universal-links",
    title: "Universal Link Intelligence",
    scenario_label: "Visible link scan summary",
    url: "http://127.0.0.1:5500/extension/test-universal-links.html",
    risk_level: "medium",
    trust_score: 62,
    phishing_probability: 0.38,
    attack_type: "Suspicious link redirection",
    summary: "A mixed page can contain trusted official links, caution links, and high-risk fake brand links.",
    signals: [
      "Trusted links: Apple, OpenAI, Claude.",
      "High-risk links: fake Apple and OpenAI login domains.",
      "Caution links: shortened or suspicious lookalike links."
    ],
    what_to_avoid: [
      "Do not follow shortened or mismatched links from untrusted pages."
    ],
    safer_action: "Use the page-wide link scan before clicking unfamiliar links."
  },
  {
    id: "medium-http",
    title: "Medium-Risk HTTP Caution",
    scenario_label: "Not Secure page",
    url: "http://example.com/login",
    risk_level: "medium",
    trust_score: 58,
    phishing_probability: 0.42,
    attack_type: "Insecure credential collection",
    summary: "HTTP alone is a caution signal; HTTP combined with login or account context is more serious.",
    signals: [
      "The page uses HTTP instead of encrypted HTTPS.",
      "The URL contains login/account context."
    ],
    what_to_avoid: [
      "Do not enter passwords or payment details on an HTTP page."
    ],
    safer_action: "Look for the official HTTPS version before entering sensitive information."
  },
  {
    id: "report-card",
    title: "Personal Security Report Card",
    scenario_label: "Local protection summary",
    url: "chrome.storage.local",
    risk_level: "low",
    trust_score: 100,
    phishing_probability: 0.0,
    attack_type: "No strong attack pattern identified",
    summary: "The report card summarizes local protection activity without storing private content.",
    signals: [
      "Tracks local summary counts only.",
      "Does not store passwords, cookies, full messages, or raw clipboard text.",
      "Includes reset controls for local stats."
    ],
    what_to_avoid: [],
    safer_action: "Use the report card to explain privacy-first local telemetry during a demo."
  }
];

globalThis.TRUSTTRACE_DEMO_SCENARIOS = TRUSTTRACE_DEMO_SCENARIOS;

# API Design

## Health Check

`GET /health`

Response:

```json
{
  "status": "ok"
}
```

## Analyze URL

`POST /api/analyze-url`

This endpoint is preserved for URL-only analysis.
The MVP 7 service worker also uses this endpoint for pre-visit URL-only checks.

Request:

```json
{
  "url": "https://example.com"
}
```

Response:

```json
{
  "url": "https://example.com",
  "risk_level": "low",
  "phishing_probability": 0.0,
  "trust_score": 100,
  "reasons": [],
  "confidence": "low",
  "trust_signals": [],
  "reputation": {
    "is_official_brand_domain": false,
    "is_high_reputation_domain": false,
    "matched_brand": "",
    "reputation_score": 50
  },
  "threat_intel": {
    "is_known_bad": false,
    "source": "none",
    "reason": "No local known-bad match."
  },
  "deep_analysis": {
    "signals": [],
    "score_delta": 0
  },
  "attack_explanation": {
    "attack_type": "Unknown / low-risk",
    "attack_category": "No strong pattern",
    "severity": "low",
    "summary": "No strong attack pattern was identified from the current checks.",
    "how_it_works": [],
    "what_to_avoid": [],
    "safer_action": "",
    "secondary_attack_types": []
  }
}
```

## Analyze Page

`POST /api/analyze-page`

This endpoint analyzes the current URL, visible webpage text, and login form metadata. For normal web URLs, URL risk contributes `45%` of the final score, page content risk contributes `30%`, and form risk contributes `25%`.

Request:

```json
{
  "url": "https://example.com",
  "page_title": "Example Domain",
  "visible_text": "visible page text here",
  "forms": [
    {
      "action": "https://example.com/login",
      "method": "post",
      "has_password_field": true,
      "has_email_or_username_field": true,
      "input_count": 3,
      "hidden_input_count": 1,
      "submit_text": "Login"
    }
  ]
}
```

## Analyze Message

`POST /api/analyze-message`

This endpoint analyzes user-selected or visible message text. It is designed for user-controlled scans from Gmail, Outlook Web, LinkedIn messages, Facebook messages, SMS-style pages, or any browser page. It does not connect to email provider APIs.

Request:

```json
{
  "source_url": "https://mail.google.com/",
  "subject": "Account Security Alert",
  "sender": "google.security.alert@gmail.com",
  "sender_type": "email",
  "message_text": "Your Google account has been suspended due to unusual activity. Verify your password immediately to avoid account closure.",
  "links": [
    {
      "text": "Google Login",
      "href": "http://secure-google-login.example.com/verify"
    }
  ]
}
```

Response:

```json
{
  "risk_level": "high",
  "phishing_probability": 1.0,
  "trust_score": 0,
  "reasons": [
    "The sender uses a personal/free email provider while claiming to represent Google.",
    "The message uses urgent language. Matched term(s): immediately.",
    "The message uses account-suspension or account-threat language. Matched term(s): suspended, unusual activity.",
    "The message asks for password, login, or security-code verification. Matched term(s): password, verify.",
    "The displayed link text mentions Google, but the actual destination is not google.com."
  ],
  "signals": {
    "sender_signals": [
      "The sender uses a personal/free email provider while claiming to represent Google."
    ],
    "message_signals": [
      "The message uses urgent language. Matched term(s): immediately.",
      "The message uses account-suspension or account-threat language. Matched term(s): suspended, unusual activity.",
      "The message asks for password, login, or security-code verification. Matched term(s): password, verify."
    ],
    "link_signals": [
      "The displayed link text mentions Google, but the actual destination is not google.com."
    ],
    "repeat_signals": []
  },
  "repeat_count": 1,
  "repeat_warning": null
}
```

### Risk Levels

- `low`: few or no suspicious rule-based indicators.
- `medium`: several warning signs are present.
- `high`: strong phishing indicators are present.

### MVP Detection Signals

- HTTP instead of HTTPS.
- Long URL length.
- Suspicious keywords such as `login`, `verify`, `account`, `secure`, `update`, `bank`, `password`, and `refund`.
- IP address in the URL hostname.
- Excessive hyphens in the hostname.
- Too many subdomains.
- `@` symbol in the URL.
- Known URL shorteners such as `bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `ow.ly`, `is.gd`, `buff.ly`, and `rebrand.ly`.
- Suspicious top-level domains such as `.xyz`, `.top`, `.click`, `.work`, `.zip`, `.country`, `.stream`, `.gq`, `.tk`, `.ml`, `.ga`, `.cf`, `.loan`, `.party`, `.download`, and `.gdn`.
- Brand impersonation keywords such as `paypal`, `amazon`, `apple`, `microsoft`, `google`, `netflix`, `facebook`, `instagram`, `bankofamerica`, `chase`, and `wells-fargo`.
- Encoded characters such as `%2F`.
- Multiple slashes after the hostname.
- Unusually long query strings.

### Page Content Signals

The page analyzer scans visible webpage text and the page title for explainable scam indicators:

- Urgent language such as `urgent`, `immediately`, `act now`, `limited time`, and `final warning`.
- Account threat language such as `suspended`, `locked`, `disabled`, `restricted`, and `unusual activity`.
- Credential language such as `password`, `login`, `verify`, `confirm identity`, and `security code`.
- Payment/refund language such as `payment failed`, `refund`, `invoice`, `billing`, and `bank account`.
- Prize/scam language such as `winner`, `congratulations`, `claim reward`, and `free gift`.
- Fear language such as `your account will be closed`, `unauthorized access`, and `security alert`.

### Form Signals

The form analyzer scans metadata collected by the browser extension for fake-login and credential-harvesting indicators:

- Password field present.
- Email or username field present.
- Form submits to a different domain than the current page.
- Form action is empty or missing.
- Form uses HTTP instead of HTTPS.
- Suspicious submit text such as `verify`, `confirm`, `update`, `unlock`, `secure`, and `continue`.
- Many hidden inputs.
- Password form appears on a suspicious URL or a page with suspicious account-verification language.

### Message Signals

The message analyzer scans subject and message text for:

- Urgency such as `urgent`, `immediately`, `act now`, `final warning`, `limited time`, and `respond now`.
- Account threats such as `suspended`, `locked`, `disabled`, `restricted`, `unusual activity`, `account closure`, and `account will be closed`.
- Credential requests such as `password`, `login`, `verify`, `confirm identity`, `security code`, `authentication code`, `one-time code`, and `OTP`.
- Payment/refund/invoice scams such as `refund`, `payment failed`, `invoice`, `billing`, `bank account`, `card declined`, and `transaction failed`.
- Prize scams such as `congratulations`, `winner`, `claim reward`, `free gift`, `lottery`, and `prize`.
- Fear/security language such as `unauthorized access`, `security alert`, `suspicious activity`, and `account compromised`.

### Sender And Link Signals

Sender identity analysis detects:

- Free email provider impersonation, such as a Gmail sender claiming to represent Google or a security team.
- Claimed brand vs sender domain mismatch.
- Simple lookalike sender domains.
- Phone number senders claiming to represent a bank, company, government, or security service.

Message link analysis detects:

- HTTP links.
- URL shorteners.
- Suspicious TLDs.
- Suspicious login/account/update words.
- Brand words in fake destination domains.
- Displayed link text that mentions a brand while the actual destination domain is not official.

### Repeated Message Detection

`POST /api/analyze-message` stores local scan history in `backend/trusttrace.db`.

- Full message bodies are not stored.
- TrustTrace AI stores a SHA-256 hash, sender, subject, source URL, short normalized preview, risk level, phishing probability, timestamps, and scan count.
- If a similar message is scanned more than once, the response includes `repeat_count`, `repeat_warning`, and `repeat_signals`.

### Scoring Model

The MVP scoring engine uses an evidence-based multi-layer pipeline. The final score is capped at `100`.

Layer 1: known threat-intelligence placeholders for PhishTank, OpenPhish cached feeds, Google Safe Browsing, URLhaus, and VirusTotal. These return neutral `not_configured` results until future integrations are added.

Layer 1 also includes a local MVP known-bad URL/domain blocklist. A local blocklist match is treated as high risk with high confidence and should trigger the pre-visit warning page.

Layer 2: reputation and legitimacy checks for official trusted brand domains, high-reputation MVP domains, Tranco, RDAP/domain age, URLScan, and certificate reputation placeholders.

Layer 3: ML and deep-analysis placeholders plus local checks for homoglyphs, punycode, typosquatting, domain entropy, IP hostnames, brand spoofing, suspicious TLDs, suspicious subdomain depth, and lookalike login/security prefixes.

- `phishing_probability` is the capped risk score divided by `100`.
- `trust_score` is `100` minus the capped risk score.
- `risk_level` is `low` below `30`, `medium` from `30` to `59`, and `high` at `60` or above.
- `confidence` describes how strong the current evidence is.
- `trust_signals` explain legitimacy indicators such as official domains or local high-reputation matches.

Brand impersonation is suspicious only when the brand appears outside the official domain. Hidden inputs, normal forms, brand names, and ordinary login/account wording are not enough by themselves to mark official high-reputation sites suspicious.

### Attack Explanation Mode

`/api/analyze-url`, `/api/analyze-page`, and `/api/analyze-message` may include `attack_explanation`.

This is rule-based explainability, not an external AI model. It classifies the strongest likely attack pattern from existing reasons and signals, then explains how the attack works, what to avoid, and a safer action.

Supported attack types include known-bad URL/malware, credential phishing, brand impersonation phishing, typosquatting/lookalike domains, insecure credential collection, suspicious link redirection, urgency/social engineering pressure, repeated scam/campaign behavior, and unknown/low-risk.

Known-bad test URLs such as `http://apple-login-security.example.com/verify`, `https://openai-login-verify.example.com/password`, `https://claude-security-login.example.com`, and `https://gemini-google-verify-account.xyz/login` are included in the local blocklist for MVP testing only. No external feed is fetched.

### HTTP / Not Secure Pages

HTTP alone is a caution signal, not automatic phishing. A plain HTTP page with no other suspicious signals should usually remain low or medium risk, with a moderately reduced trust score.

HTTP becomes more serious when combined with login, account, password, payment, billing, bank, or verification context. HTTP pages with password or credential-entry forms are treated as high risk because credentials would be submitted from an unencrypted page.

### Pre-Visit Warning Thresholds

The Chrome extension uses `/api/analyze-url` before or during top-level navigation:

- High-risk interstitial when `trust_score <= 30`, `phishing_probability >= 0.75`, or `risk_level == "high"` with `confidence == "high"`.
- Medium-risk caution banner when `trust_score` is between `31` and `60`, or `risk_level == "medium"`.
- Low-risk URLs open normally.

Pre-visit checks send only the destination URL. Page content is not collected for warning interstitials.

For `/api/analyze-page`, local development URLs skip URL risk scoring but still run page content and form analysis. This makes it possible to test suspicious local HTML pages served from `localhost` or `127.0.0.1`.

If a password form appears with suspicious content or a suspicious URL, TrustTrace AI adds an extra risk boost because that combination is common in credential-harvesting pages.

### Local Development URLs

During MVP testing, local development hosts include `localhost`, `127.0.0.1`, `0.0.0.0`, and `::1`.

For `POST /api/analyze-url`, local development URLs are treated as safe and return `low` risk with `trust_score` `100`.

Example response:

```json
{
  "url": "http://127.0.0.1:8000/health",
  "risk_level": "low",
  "phishing_probability": 0.0,
  "trust_score": 100,
  "reasons": ["Local development URL detected; phishing risk scoring skipped."]
}
```

For `POST /api/analyze-page`, local development URLs skip URL-based scoring but still analyze `page_title`, `visible_text`, and `forms`. If local test page content or fake login forms contain phishing indicators, the final result can still become `medium` or `high` risk.

Example local page request:

```json
{
  "url": "http://localhost:8000/test-phishing.html",
  "page_title": "Security Alert",
  "visible_text": "Urgent final warning. Your account is suspended and your account will be closed. Verify your password immediately.",
  "forms": [
    {
      "action": "",
      "method": "post",
      "has_password_field": true,
      "has_email_or_username_field": true,
      "input_count": 3,
      "hidden_input_count": 1,
      "submit_text": "Verify Account"
    }
  ]
}
```

Example local page response:

```json
{
  "url": "http://localhost:8000/test-phishing.html",
  "risk_level": "high",
  "phishing_probability": 1.0,
  "trust_score": 0,
  "reasons": [
    "Local development URL detected; URL risk scoring skipped, but page content and forms were analyzed.",
    "The page uses urgent language that may pressure users to act quickly. Matched term(s): final warning, immediately, urgent.",
    "The page mentions account restrictions or unusual activity. Matched term(s): suspended.",
    "The page asks about credentials or identity verification. Matched term(s): password, verify.",
    "The page uses fear-based security language to create urgency. Matched term(s): security alert, your account will be closed.",
    "The page combines urgent language, account-threat language, and credential verification language.",
    "The page combines security-alert language with credential requests and urgency.",
    "Form 1: A password field was detected.",
    "Form 1: An email or username field was detected.",
    "Form 1: The form asks for both an email or username and a password.",
    "Form 1: The form action is missing, which can make destination behavior unclear.",
    "Form 1: The submit button uses suspicious action word(s): verify.",
    "Form 1: The form contains 1 hidden input(s).",
    "Form 1: A password field was detected on a page with suspicious account-verification or security-alert language."
  ],
  "signals": {
    "url_signals": [],
    "content_signals": [
      "The page uses urgent language that may pressure users to act quickly. Matched term(s): final warning, immediately, urgent.",
      "The page mentions account restrictions or unusual activity. Matched term(s): suspended.",
      "The page asks about credentials or identity verification. Matched term(s): password, verify.",
      "The page uses fear-based security language to create urgency. Matched term(s): security alert, your account will be closed.",
      "The page combines urgent language, account-threat language, and credential verification language.",
      "The page combines security-alert language with credential requests and urgency."
    ],
    "form_signals": [
      "Form 1: A password field was detected.",
      "Form 1: An email or username field was detected.",
      "Form 1: The form asks for both an email or username and a password.",
      "Form 1: The form action is missing, which can make destination behavior unclear.",
      "Form 1: The submit button uses suspicious action word(s): verify.",
      "Form 1: The form contains 1 hidden input(s).",
      "Form 1: A password field was detected on a page with suspicious account-verification or security-alert language."
    ]
  }
}
```

## Example Test URLs

### Safe URL

```json
{
  "url": "https://example.com"
}
```

Expected result: `low` risk, high trust score, and no obvious phishing indicators.

### Suspicious Brand Impersonation URL

```json
{
  "url": "http://paypal-secure-login.verify-account.security.example.com/update"
}
```

Expected result: `high` risk because it uses HTTP, includes phishing keywords, contains a brand name, has multiple subdomains, and uses hyphenated impersonation-style wording.

### Shortened URL

```json
{
  "url": "https://bit.ly/3SuspiciousLink"
}
```

Expected result: elevated risk because known URL shorteners can hide the final destination.

### Suspicious TLD URL

```json
{
  "url": "https://account-verify-example.xyz/login"
}
```

Expected result: elevated risk because the URL includes phishing keywords, hyphens, and a suspicious top-level domain.

### Localhost URL

```json
{
  "url": "http://localhost:8000"
}
```

Expected result: `low` risk with risk scoring skipped for local MVP development.

For `/api/analyze-page`, this same localhost URL can still become `medium` or `high` risk if the visible page text or form metadata contains phishing or credential-harvesting indicators.

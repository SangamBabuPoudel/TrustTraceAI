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
  "reasons": []
}
```

## Analyze Page

`POST /api/analyze-page`

This endpoint analyzes both the current URL and visible webpage text. For normal web URLs, URL risk contributes `60%` of the final score and page content risk contributes `40%`.

Request:

```json
{
  "url": "https://example.com",
  "page_title": "Example Domain",
  "visible_text": "visible page text here"
}
```

Response:

```json
{
  "url": "https://example.com",
  "risk_level": "low",
  "phishing_probability": 0.0,
  "trust_score": 100,
  "reasons": ["No obvious phishing indicators were found by the MVP checks."],
  "signals": {
    "url_signals": [],
    "content_signals": []
  }
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
- Suspicious top-level domains such as `.xyz`, `.top`, `.click`, `.work`, `.zip`, `.country`, `.stream`, `.gq`, `.tk`, and `.ml`.
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

### Scoring Model

The MVP scoring engine uses transparent rule weights. Each detected signal adds risk points. The final score is capped at `100`.

- `phishing_probability` is the capped risk score divided by `100`.
- `trust_score` is `100` minus the capped risk score.
- `risk_level` is `low` below `30`, `medium` from `30` to `59`, and `high` at `60` or above.

For `/api/analyze-page`, local development URLs skip URL risk scoring but still run page content analysis. This makes it possible to test suspicious local HTML pages served from `localhost` or `127.0.0.1`.

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

For `POST /api/analyze-page`, local development URLs skip URL-based scoring but still analyze `page_title` and `visible_text`. If local test page content contains phishing or scam language, the final result can still become `medium` or `high` risk based on content signals.

Example local page request:

```json
{
  "url": "http://localhost:8000/test-phishing.html",
  "page_title": "Security Alert",
  "visible_text": "Urgent final warning. Your account is suspended and your account will be closed. Verify your password immediately to claim reward."
}
```

Example local page response:

```json
{
  "url": "http://localhost:8000/test-phishing.html",
  "risk_level": "high",
  "phishing_probability": 0.9,
  "trust_score": 10,
  "reasons": [
    "Local development URL detected; URL risk scoring skipped, but page content was analyzed.",
    "The page uses urgent language that may pressure users to act quickly. Matched term(s): final warning, immediately, urgent.",
    "The page mentions account restrictions or unusual activity. Matched term(s): suspended.",
    "The page asks about credentials or identity verification. Matched term(s): password, verify.",
    "The page uses prize or reward wording commonly found in scams. Matched term(s): claim reward.",
    "The page uses fear-based security language to create urgency. Matched term(s): security alert, your account will be closed."
  ],
  "signals": {
    "url_signals": [
      "Local development URL detected; URL risk scoring skipped, but page content was analyzed."
    ],
    "content_signals": [
      "The page uses urgent language that may pressure users to act quickly. Matched term(s): final warning, immediately, urgent.",
      "The page mentions account restrictions or unusual activity. Matched term(s): suspended.",
      "The page asks about credentials or identity verification. Matched term(s): password, verify.",
      "The page uses prize or reward wording commonly found in scams. Matched term(s): claim reward.",
      "The page uses fear-based security language to create urgency. Matched term(s): security alert, your account will be closed."
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

For `/api/analyze-page`, this same localhost URL can still become `medium` or `high` risk if the visible page text contains phishing or scam indicators.

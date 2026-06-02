# API Design

TrustTrace AI exposes a small local FastAPI API. The Chrome extension calls these endpoints from the popup, content script, and service worker.

## `GET /health`

Health check endpoint for local setup verification.

Response:

```json
{
  "status": "ok"
}
```

## `POST /api/analyze-url`

Analyzes a single URL. Used by the popup, pre-visit warning service worker, search result annotations, and universal link scanning.

Request:

```json
{
  "url": "http://apple-login-security.example.com/verify"
}
```

Example response:

```json
{
  "url": "http://apple-login-security.example.com/verify",
  "risk_level": "high",
  "phishing_probability": 1.0,
  "trust_score": 0,
  "reasons": [
    "URL matched local MVP known-bad blocklist."
  ],
  "confidence": "high",
  "trust_signals": [],
  "reputation": {
    "is_official_brand_domain": false,
    "is_high_reputation_domain": false,
    "matched_brand": "apple",
    "reputation_score": 20
  },
  "threat_intel": {
    "is_known_bad": true,
    "source": "local_blocklist",
    "reason": "URL matched local MVP known-bad blocklist."
  },
  "deep_analysis": {
    "signals": [],
    "score_delta": 0
  },
  "attack_explanation": {
    "attack_type": "Known-bad URL / malware",
    "attack_category": "Known threat intelligence",
    "severity": "high",
    "summary": "This URL appears in a known-bad threat list or local blocklist.",
    "how_it_works": [
      "The destination matched a known-bad URL or domain list."
    ],
    "what_to_avoid": [
      "Do not visit the link unless you are testing in a safe environment."
    ],
    "safer_action": "Close the page and use a trusted source or official website instead.",
    "secondary_attack_types": []
  }
}
```

## `POST /api/analyze-page`

Analyzes the current URL, visible page text, and form metadata. Used by the popup website scan.

Request:

```json
{
  "url": "http://127.0.0.1:5500/extension/test-phishing.html",
  "page_title": "Security Alert",
  "visible_text": "urgent account suspended verify immediately",
  "forms": [
    {
      "action": "http://example.com/login",
      "method": "post",
      "has_password_field": true,
      "has_email_or_username_field": true,
      "input_count": 2,
      "hidden_input_count": 0,
      "submit_text": "Verify Account"
    }
  ]
}
```

Example response fields:

```json
{
  "url": "http://127.0.0.1:5500/extension/test-phishing.html",
  "risk_level": "high",
  "phishing_probability": 0.85,
  "trust_score": 15,
  "reasons": [
    "Local development URL detected; URL risk scoring skipped, but page content and forms were analyzed.",
    "The page uses urgent language.",
    "A password field was detected on a page with suspicious account-verification language."
  ],
  "signals": {
    "url_signals": [],
    "content_signals": [],
    "form_signals": []
  },
  "attack_explanation": {
    "attack_type": "Credential phishing",
    "summary": "This may be trying to collect login credentials or security codes.",
    "what_to_avoid": [
      "Do not enter passwords or security codes."
    ],
    "safer_action": "Go directly to the official website by typing the address yourself or using a trusted bookmark."
  }
}
```

## `POST /api/analyze-message`

Analyzes user-selected or visible message text. It does not connect to Gmail, Outlook, or other email provider APIs.

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

Example response fields:

```json
{
  "risk_level": "high",
  "phishing_probability": 1.0,
  "trust_score": 0,
  "reasons": [
    "The sender uses a personal/free email provider while claiming to represent Google.",
    "The message uses urgent language.",
    "The message asks for password, login, or security-code verification.",
    "The displayed link text mentions Google, but the actual destination is not google.com."
  ],
  "signals": {
    "sender_signals": [],
    "message_signals": [],
    "link_signals": [],
    "repeat_signals": []
  },
  "repeat_count": 1,
  "repeat_warning": null,
  "attack_explanation": {
    "attack_type": "Credential phishing",
    "attack_category": "Credential theft",
    "severity": "high",
    "summary": "This may be trying to collect login credentials or security codes."
  }
}
```

## Shared Response Fields

| Field | Meaning |
|---|---|
| `risk_level` | `low`, `medium`, or `high`. |
| `phishing_probability` | Rule-based probability from `0.0` to `1.0`. |
| `trust_score` | Human-friendly score from `0` to `100`. |
| `reasons` | Human-readable evidence. |
| `signals` | Grouped evidence for page/message scans. |
| `confidence` | Strength of current evidence. |
| `trust_signals` | Positive legitimacy evidence. |
| `reputation` | Official/high-reputation domain metadata. |
| `threat_intel` | Local blocklist result and future threat-intel placeholder output. |
| `deep_analysis` | Structured deep URL heuristic signals. |
| `attack_explanation` | Attack type, summary, what to avoid, and safer action. |

## Scoring Notes

- HTTP alone is a caution signal, not automatic phishing.
- HTTP plus login/password/payment context is more serious.
- HTTP plus a password form is high risk.
- Official trusted HTTPS domains suppress weak false-positive signals.
- Local known-bad blocklist matches are high risk.
- External APIs and ML are not active in this MVP.

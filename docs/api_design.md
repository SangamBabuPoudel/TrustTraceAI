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

Analyzes the current URL, visible page text, form metadata, and optional visual metadata. Used by the popup website scan.

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
  ],
  "visual_metadata": {
    "document_title": "Security Alert",
    "primary_headings": ["Apple ID"],
    "favicons": [
      {
        "href": "https://example.com/apple-logo-favicon.ico",
        "type": "image/x-icon",
        "rel": "icon"
      }
    ],
    "images": [
      {
        "src": "https://example.com/apple-logo.png",
        "alt": "Apple logo",
        "title": "Apple logo",
        "class_name": "brand-logo",
        "id": "",
        "width": 62,
        "height": 62,
        "nearby_text": "Apple ID account locked security verification required"
      }
    ],
    "logo_candidates": [],
    "button_texts": ["Verify Apple ID"],
    "input_labels": ["Email or Apple ID", "Password"],
    "brand_like_text": ["apple", "apple id"],
    "color_hints": [],
    "layout_hints": {
      "has_centered_login_card": true,
      "has_fullscreen_login_layout": true,
      "has_minimal_login_page": true
    }
  }
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
    "form_signals": [],
    "visual_clone_signals": [
      "Page claims to represent Apple, but the domain is not an official Apple domain."
    ]
  },
  "visual_clone": {
    "is_visual_clone_suspected": true,
    "visual_clone_score": 100,
    "visual_clone_confidence": "high",
    "primary_clone_brand": "apple",
    "claimed_brands": ["apple"],
    "signals": [
      {
        "type": "brand_domain_mismatch",
        "severity": "high",
        "brand": "Apple",
        "message": "Page claims to represent Apple, but the domain is not an official Apple domain."
      }
    ]
  },
  "attack_explanation": {
    "attack_type": "Visual brand cloning / fake login page",
    "summary": "This page appears to copy the visual identity of a trusted service while being hosted on a non-official domain.",
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
| `visual_clone` | Metadata-based visual brand clone result for page scans. |

## Scoring Notes

- HTTP alone is a caution signal, not automatic phishing.
- HTTP plus login/password/payment context is more serious.
- HTTP plus a password form is high risk.
- Official trusted HTTPS domains suppress weak false-positive signals.
- Brand visual claims on official trusted domains do not create visual clone warnings.
- Trusted commerce/retailer domains can mention brands in product or marketplace context without being treated as brand impersonation.
- Brand impersonation requires suspicious identity/login/security context, suspicious domain patterns, credential language, or low-reputation context.
- Visual Clone Intelligence uses DOM metadata only; it does not collect screenshots or image binaries.
- Local known-bad blocklist matches are high risk.
- External APIs and ML are not active in this MVP.

## Regression Examples

Trusted retailer product context:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://www.verizon.com/shop/online/free-cell-phones/apple/"}'
```

Expected: low risk, high trust score, no Apple impersonation warning. A trust signal may say Apple appears in product listing context.

Fake Apple login/security domain:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://apple-login-security.example.com/verify"}'
```

Expected: high risk.

Official Apple support page:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://support.apple.com"}'
```

Expected: low risk with official Apple trust signal.

Trusted commerce search page:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://www.bestbuy.com/site/searchpage.jsp?st=apple+iphone"}'
```

Expected: low or low-medium risk, no Apple impersonation warning.

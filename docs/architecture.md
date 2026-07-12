# Architecture

TrustTrace AI is a local Chrome Extension MV3 and FastAPI system for explainable browser security analysis.

## High-Level Diagram

```text
User Browser
  |
  |-- Popup UI
  |-- Content Script
  |-- MV3 Service Worker
  |
  v
Local FastAPI Backend
  |
  |-- URL Feature Extractor
  |-- Reputation Service
  |-- Local Threat Intel Service
  |-- Deep URL Analysis Service
  |-- Page Content Analyzer
  |-- Form Analyzer
  |-- Visual Clone Analyzer
  |-- Message Analyzer
  |-- Sender Identity Analyzer
  |-- Message Fingerprint Service
  |-- Attack Explanation Service
  |-- Local Security Report Metrics
  |-- Clipboard Guardian Local Checks
  |
  v
Risk Response
  |
  |-- Popup Dashboard
  |-- Warning Interstitial
  |-- Caution Banner
  |-- Search Result Badges
  |-- Universal Link Summary
  |-- Security Report Card
  |-- Clipboard Guardian Result
  |-- Visual Clone Intelligence Panel
  |-- Demo Mode Cards
  |-- Personal Adaptive Trust
```

## Chrome Extension

- `popup.html`, `popup.css`, `popup.js`: interactive dashboard for page scans, message scans, link scans, copy report, and attack explanations.
- `demoScenarios.js`: static, clearly labeled sample scenarios for reviewer-friendly Demo Mode.
- `adaptiveTrust.js`: optional local domain-level learning model that stores minimal trust metadata in `chrome.storage.local`.
- `community_reputation_service.py`: future backend placeholder for thresholded, abuse-resistant community reputation. It is not wired into scoring today.
- `demo.html`, `demo.css`, `demo.js`: optional static portfolio dashboard for screen recording and screenshots.
- `content.js`: collects visible page text, form metadata, visual metadata, message candidates, visible links, and search result links. It also injects caution banners and search result badges.
- `background.js`: MV3 service worker for pre-visit URL checks, high-risk warning redirects, high-risk cache, session bypass, and URL analysis requests from content scripts.
- `warning.html`, `warning.css`, `warning.js`: high-risk interstitial with risk evidence and attack explanation.

## Backend

The backend is a local FastAPI app with three primary analysis endpoints:

- `POST /api/analyze-url`
- `POST /api/analyze-page`
- `POST /api/analyze-message`

Each endpoint returns explainable fields such as `risk_level`, `phishing_probability`, `trust_score`, `reasons`, grouped `signals`, `reputation`, `deep_analysis`, and `attack_explanation` where applicable.

## Multi-Layer Scoring Pipeline

```text
Incoming URL / Page / Message
  |
  v
Layer 1: Local known-bad blocklist + future threat intel placeholders
  |
  v
Layer 2: Official domain and reputation checks
  |      includes trusted commerce/product context
  |
  v
Layer 3: URL/domain heuristics
  |
  v
Layer 4: Page, form, visual clone, sender, message, and link analysis
  |
  v
Layer 5: Attack Explanation Mode
  |
  v
Layer 6: Optional Personal Adaptive Trust
  |
  v
Risk response rendered in extension UI
```

## Warning Flow

1. The service worker listens for top-level HTTP/HTTPS navigation.
2. It skips local development URLs, browser URLs, extension URLs, `mailto:`, and `tel:`.
3. It calls `/api/analyze-url` with the destination URL only.
4. High-risk results redirect to `warning.html`.
5. Medium-risk results allow the page to load and inject a caution banner.
6. Low-risk results continue normally.

## Universal Link Intelligence

The content script extracts visible links from normal pages and search result pages. Search result annotation runs automatically on supported search engines. Page-wide link scanning is user-controlled from the popup and scans unique visible URLs with limited concurrency.

## Attack Explanation Mode

The attack explanation service uses existing reasons and signals to classify a likely attack type. It does not call an external AI model. It provides:

- Attack type
- Attack category
- Severity
- Summary
- How it works
- What to avoid
- Safer action

## Visual Clone Intelligence

Visual Clone Intelligence analyzes DOM metadata for brand clone patterns. It uses document title, headings, favicon links, image alt/title/src metadata, logo candidates, button text, input labels, brand-like text, and login layout hints.

The analyzer flags a page when it claims a trusted brand, is not on an official brand domain, and contains login, verification, security, payment, or credential-like behavior. Official trusted domains suppress clone warnings when the visual brand claim matches the domain.

Trusted commerce domains such as Verizon, Best Buy, Amazon, Walmart, Target, Costco, AT&T, and T-Mobile can mention brands in product listings without being treated as fake brand identity pages. Product context is separated from identity/login context before clone scoring is applied.

It does not collect screenshots, image binaries, canvas pixels, or visual recordings. Future work could add screenshot similarity or computer-vision models only after explicit privacy review.

## Demo Mode

Demo Mode is an optional popup section that renders static sample scenarios for major TrustTrace AI capabilities. It is clearly labeled as demo output, does not call external APIs, does not scan private content, and does not update the real Security Report Card.

The optional `extension/demo.html` page provides a larger static dashboard for portfolio recordings. It uses the same scenario data as the popup and links to local test pages served from `http://127.0.0.1:5500`.

## Personal Security Report Card

The extension stores local-only summary counters in `chrome.storage.local`. The report card tracks totals such as URL/page/message/link scans, high-risk blocks, medium cautions, suspicious messages, fake login form detections, repeated scam warnings, and attack type counts.

It does not store passwords, cookies, full URLs, full message text, form values, personal identity, or full browsing history. Users can reset the local stats from the popup.

## Personal Adaptive Trust

Personal Adaptive Trust is an opt-in frontend layer that helps reduce repeated false positives on familiar safe domains for one user's browser only. It stores only domain-level metadata in `chrome.storage.local`, such as scan counts, safe/caution/high-risk counts, user feedback counts, last risk level, last trust score, last seen timestamp, and a bounded learned adjustment.

The stored key is the sanitized hostname only, for example `example.com`. Full URL paths, query strings, page text, messages, clipboard content, passwords, cookies, form values, tokens, and browsing history are not stored.

Adaptive adjustments are intentionally small: positive adjustments are capped at `+10`, negative adjustments are capped at `-15`, and positive learning cannot override strong phishing evidence such as known-bad blocklist hits, high-confidence visual clones, fake login forms, brand impersonation, typosquatting, or credential-phishing signals.

## Personal Adaptive Trust Vs Community Reputation

Personal Adaptive Trust is local and private. One user can mark a domain trusted, suspicious, or false positive, but that feedback affects only that user's current browser.

Community reputation is a future/global layer. It should require many independent reports before any global signal is considered. The placeholder `community_reputation_service.py` documents thresholds and abuse controls:

- 1-2 reports: local/user-level signal only.
- 3-9 independent reports: weak community signal.
- 10-24 independent reports: medium community confidence.
- 25+ independent reports: stronger community reputation signal.

Future community reporting must use rate limits, deduplication, independent reporter counts, sanitized domain-only storage, and verified-source weighting. It must not let attackers mass-mark phishing domains as safe, competitors mass-report legitimate domains, or accidental user feedback change global trust for everyone.

## Clipboard Guardian Mode

Clipboard Guardian is off by default. When enabled, it performs local checks for suspicious clipboard content and copy-button mismatch risks. The popup reads clipboard text only when the user clicks Scan Clipboard Now.

Non-URL clipboard text is analyzed locally in the extension and is not sent to the backend. If the clipboard contains a URL, the popup may send only that URL to `/api/analyze-url` after the user initiates the scan.

## Current Limitations

- External threat intelligence APIs are placeholders only.
- Machine learning models are not implemented yet.
- Personal Adaptive Trust is a local feedback layer, not a cloud model and not a production reputation system.
- Community reputation is a documented future placeholder only.
- This is a local MVP, not a production security product.
- Browser UI structure can change, so search result annotation may need maintenance over time.

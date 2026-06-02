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
  |-- Message Analyzer
  |-- Sender Identity Analyzer
  |-- Message Fingerprint Service
  |-- Attack Explanation Service
  |-- Local Security Report Metrics
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
```

## Chrome Extension

- `popup.html`, `popup.css`, `popup.js`: interactive dashboard for page scans, message scans, link scans, copy report, and attack explanations.
- `content.js`: collects visible page text, form metadata, message candidates, visible links, and search result links. It also injects caution banners and search result badges.
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
  |
  v
Layer 3: URL/domain heuristics
  |
  v
Layer 4: Page, form, sender, message, and link analysis
  |
  v
Layer 5: Attack Explanation Mode
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

## Personal Security Report Card

The extension stores local-only summary counters in `chrome.storage.local`. The report card tracks totals such as URL/page/message/link scans, high-risk blocks, medium cautions, suspicious messages, fake login form detections, repeated scam warnings, and attack type counts.

It does not store passwords, cookies, full URLs, full message text, form values, personal identity, or full browsing history. Users can reset the local stats from the popup.

## Current Limitations

- External threat intelligence APIs are placeholders only.
- Machine learning models are not implemented yet.
- This is a local MVP, not a production security product.
- Browser UI structure can change, so search result annotation may need maintenance over time.

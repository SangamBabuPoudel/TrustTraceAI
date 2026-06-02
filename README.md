# TrustTrace AI - Explainable AI Browser Security Extension

An explainable browser security extension that detects phishing websites, suspicious links, fake login forms, scam messages, and brand impersonation using layered risk scoring and real-time warnings.

## Problem Statement

Many phishing defenses rely on simple blocklists or single-signal checks. That approach can miss newer scams, and it can also create false positives when a legitimate website uses normal login, account, or form language.

TrustTrace AI combines multiple explainable signals: URL structure, domain legitimacy, local reputation, page content, login forms, message text, sender identity, link mismatch, repeated-message history, and attack explanations. The goal is not just to say “risky” or “safe,” but to explain what the attack might be and what the user should avoid doing.

This is a local MVP portfolio project. External threat intelligence APIs and machine learning models are designed as future integration points, not claimed as production integrations today.

## Key Features

| Feature | What it does |
|---|---|
| Real-time URL risk scoring | Scores URLs through a local FastAPI backend. |
| Trust score and phishing probability | Returns `trust_score`, `phishing_probability`, and `risk_level`. |
| Official domain/reputation layer | Reduces false positives for trusted domains like Apple, OpenAI, Google, and Microsoft. |
| Deep URL heuristics | Detects suspicious TLDs, IP hosts, punycode, homoglyphs, typosquatting, and brand spoofing. |
| Page content scanning | Checks visible text for urgency, credential, account threat, payment, and scam language. |
| Fake login form detection | Detects suspicious password forms, cross-domain form actions, missing actions, and HTTP credential collection. |
| Email/message threat detection | User-controlled scan of selected or visible message text. |
| Sender identity analysis | Flags free-email impersonation, brand/domain mismatches, and suspicious phone senders. |
| Repeated scam message detection | Stores local message hashes to detect repeated similar messages without storing full bodies. |
| Universal link intelligence | Scans visible links on any page and summarizes trusted, caution, high-risk, and unknown links. |
| Search result annotation | Adds TrustTrace risk badges beside visible Google, Bing, DuckDuckGo, and Yahoo results. |
| Pre-visit high-risk warning page | Redirects high-risk navigation to a serious warning interstitial. |
| Medium-risk caution banner | Injects a yellow caution banner for medium-risk pages. |
| Attack explanation mode | Explains attack type, how it works, what to avoid, and safer action. |
| Privacy-first design | Local backend, no cookies/password collection, user-controlled message scans. |

## Architecture Overview

```text
Chrome Extension
  popup UI | content script | service worker
        |
        v
FastAPI Backend
        |
        v
Multi-Layer Threat Scoring Pipeline
        |
        v
Popup Dashboard | Warning Page | Caution Banner | Search Badges
```

The extension collects only the data needed for the selected workflow. The backend applies rule-based scoring and returns explainable risk results. The UI then displays the trust score, grouped signals, and attack explanation.

## Multi-Layer Detection Pipeline

1. Local known-bad / future threat intelligence
   - Local MVP blocklist for safe test domains.
   - Placeholders for Google Safe Browsing, PhishTank, OpenPhish, URLHaus, VirusTotal, and hosts feeds.
2. Reputation and legitimacy
   - Official trusted brand domain verification.
   - Local high-reputation allowlist for MVP testing.
   - Future placeholders for Tranco, RDAP/domain age, URLScan, and certificate reputation.
3. URL and domain heuristics
   - HTTP, suspicious TLDs, IP hosts, encoded characters, URL shorteners, long queries, typosquatting, punycode, homoglyphs, and brand spoofing.
4. Page/form/message analysis
   - Visible text, fake login forms, sender identity, message links, link text/domain mismatch, and repeated-message detection.
5. Attack explanation engine
   - Rule-based classification of likely attack type with educational guidance.
6. Future ML/community learning
   - Placeholder architecture for URL classifiers, community reports, and richer threat intelligence.

## Screenshots

These are placeholders for GitHub portfolio screenshots.

![Popup Dashboard](docs/screenshots/popup-dashboard.png)
![High-Risk Warning Page](docs/screenshots/high-risk-warning.png)
![Search Result Badges](docs/screenshots/search-result-badges.png)
![Universal Link Scan Summary](docs/screenshots/universal-link-scan.png)
![Email Message Scan Result](docs/screenshots/message-scan-result.png)
![Attack Explanation Mode](docs/screenshots/attack-explanation-mode.png)

## Tech Stack

- Chrome Extension Manifest V3
- JavaScript, HTML, CSS
- Python
- FastAPI
- Pydantic
- SQLite
- Git/GitHub
- Rule-based explainable scoring
- Future-ready API/ML placeholders

## Local Setup

1. Clone the repository.

```bash
git clone <your-repo-url>
cd TrustTraceAI
```

2. Create and activate a Python virtual environment.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
```

3. Install backend dependencies.

```bash
pip install -r requirements.txt
```

4. Run the FastAPI backend.

```bash
python3 -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

5. Load the Chrome extension.

- Open `chrome://extensions`
- Enable Developer mode
- Click Load unpacked
- Select the `extension/` folder

6. Start a local test server from the repository root.

```bash
cd ..
python3 -m http.server 5500
```

7. Open local test pages in Chrome.

```text
http://127.0.0.1:5500/extension/test-phishing.html
http://127.0.0.1:5500/extension/test-scam-message.html
http://127.0.0.1:5500/extension/test-previsit-links.html
http://127.0.0.1:5500/extension/test-universal-links.html
http://127.0.0.1:5500/extension/test-attack-explanations.html
```

## Demo Workflow

Use this as a quick portfolio walkthrough:

1. Scan an official website such as `https://www.apple.com` or `https://openai.com`.
   - Show low risk, high trust score, and trust signals.
2. Scan a fake phishing URL such as `http://apple-login-security.example.com/verify`.
   - Show high risk, local blocklist/deep URL signals, and attack explanation.
3. Click a fake high-risk link from `test-previsit-links.html`.
   - Show the warning page and Proceed Anyway session bypass.
4. Scan `test-phishing.html`.
   - Show fake login form detection and credential-harvesting explanation.
5. Scan `test-scam-message.html`.
   - Show sender impersonation, message threat detection, suspicious link analysis, and repeated scan count.
6. Scan links on `test-universal-links.html`.
   - Show total scanned links, trusted/caution/high-risk counts, and top risky links.
7. Open a Google search page.
   - Show TrustTrace search result badges beside visible results.

## Testing Pages

- `extension/test-phishing.html` - local fake login page.
- `extension/test-scam-message.html` - scam email/message cards.
- `extension/test-previsit-links.html` - safe and risky navigation links.
- `extension/test-universal-links.html` - mixed visible links for page-wide scanning.
- `extension/test-attack-explanations.html` - examples for attack explanation mode.

## Privacy And Safety

- Pre-visit warnings use URL-only checks.
- TrustTrace AI does not collect passwords.
- TrustTrace AI does not collect cookies.
- Email/message scans are user-controlled.
- Link scanning uses visible URLs plus lightweight link text/context only.
- Repeated message detection stores hashes and short metadata, not full message bodies.
- API keys are not stored in the frontend; external APIs are future backend integrations.
- The MVP runs locally and does not send data to third-party threat intelligence services.

## Roadmap

Completed:

- MVP 1: Clean extension and FastAPI foundation.
- MVP 2: URL phishing analysis.
- MVP 3: Reputation and legitimacy layer.
- MVP 4: Page content scanning.
- MVP 5: Fake login form detection.
- MVP 6: Email/message threat detection.
- MVP 7: Pre-visit warning page and caution banner.
- MVP 8: Local threat intelligence, deep URL heuristics, universal link intelligence, and search result annotation.
- MVP 9: Attack Explanation Mode.

Future:

- Real Google Safe Browsing / PhishTank / URLHaus integration.
- Tranco/RDAP/URLScan integration.
- ML URL classifier.
- QR code phishing scanner.
- Community threat intelligence.
- Personal Security Report Card.

## Resume Bullets

- Built TrustTrace AI, a Chrome Extension MV3 and FastAPI cybersecurity tool that detects phishing URLs, fake login forms, scam messages, sender impersonation, suspicious links, and repeated campaign patterns with explainable risk scoring.
- Designed a multi-layer threat pipeline combining local reputation checks, URL/domain heuristics, page/form/message analysis, pre-visit warnings, search result annotations, and rule-based attack explanations.
- Implemented privacy-first browser security workflows including user-controlled message scanning, URL-only pre-visit checks, local SQLite hash-based repeat detection, and no cookie/password collection.

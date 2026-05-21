# TrustTrace AI

TrustTrace AI is an explainable browser security extension for detecting phishing websites, scam links, fake login forms, suspicious emails/messages, malicious URLs, OCR screenshot scams, and dark patterns.

This repository currently contains a clean local MVP foundation. It uses a Chrome Extension Manifest V3 popup and a FastAPI backend with simple rule-based URL, visible page content, and fake login form analysis. Machine learning and threat intelligence APIs are intentionally not included yet.

## Problem Statement

Phishing and scam websites often rely on small signals that users can miss: insecure HTTP pages, deceptive keywords, long URLs, IP-based links, excessive subdomains, and confusing symbols. TrustTrace AI aims to make those signals visible, explainable, and easy to understand.

## Key Features

- Chrome extension popup that reads the current tab URL and visible page text.
- Local FastAPI backend.
- `GET /health` endpoint.
- `POST /api/analyze-url` endpoint.
- `POST /api/analyze-page` endpoint.
- Rule-based URL risk detection.
- Rule-based page content scam signal detection.
- Rule-based fake login form and credential-harvesting detection.
- Explainable reasons for detected risk signals.
- Beginner-readable modular code.

## Tech Stack

- Chrome Extension Manifest V3
- HTML, CSS, and JavaScript
- Python
- FastAPI
- Pydantic
- Uvicorn

## MVP Scope

Included:

- URL analysis.
- Visible page content analysis.
- Fake login form detection.
- Local-only backend.
- Rule-based risk scoring.
- Explainable output.
- Documentation for architecture, API design, privacy, roadmap, and threat model.

Not included yet:

- Machine learning.
- Threat intelligence APIs.
- Screenshot OCR.
- Email/message analysis.
- Production deployment.

## Folder Structure

```text
TrustTraceAI/
  extension/
    manifest.json
    popup.html
    popup.js
    popup.css
    background.js
    content.js
    icons/
  backend/
    app/
      main.py
      routes/
        analyze.py
      services/
        url_feature_extractor.py
        risk_scoring_engine.py
        explanation_engine.py
        page_content_analyzer.py
        form_analyzer.py
      models/
        schemas.py
    requirements.txt
    .env.example
  ml/
    data/
      raw/
      processed/
    notebooks/
    training/
    saved_models/
  docs/
    architecture.md
    roadmap.md
    api_design.md
    privacy_design.md
    threat_model.md
  README.md
  .gitignore
```

## Setup Instructions

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Check the API:

```bash
curl http://127.0.0.1:8000/health
```

Analyze a URL:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://secure-login-bank.example.com/verify/account"}'
```

Analyze a page:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze-page \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","page_title":"Example Domain","visible_text":"Example visible page text","forms":[]}'
```

### Chrome Extension

1. Open Chrome and go to `chrome://extensions`.
2. Enable Developer mode.
3. Select Load unpacked.
4. Choose the `extension/` folder.
5. Start the FastAPI backend locally.
6. Open any website and click the TrustTrace AI extension popup.

## Roadmap

- Phase 1: Clean MVP foundation.
- Phase 2: Page content scanning, fake login form detection, and browser page analysis.
- Phase 3: Email and message scam detection.
- Phase 4: OCR screenshot scam analysis.
- Phase 5: Machine learning experiments.
- Phase 6: Optional threat intelligence integrations.
- Phase 7: Product hardening and deployment preparation.

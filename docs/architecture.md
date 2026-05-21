# TrustTrace AI Architecture

TrustTrace AI starts as a local browser extension plus FastAPI backend.

## Components

- Chrome extension popup: reads the active tab URL and displays the analysis result.
- FastAPI backend: exposes local analysis endpoints for the extension.
- URL feature extractor: turns a URL into simple security signals.
- Risk scoring engine: converts signals into a risk level, phishing probability, and trust score.
- Explanation engine: converts detected signals into beginner-readable reasons.
- ML workspace: reserved for future datasets, notebooks, training, and saved models.

## MVP Flow

1. The user opens the extension popup.
2. The popup reads the active browser tab URL.
3. The popup sends the URL to `POST /api/analyze-url`.
4. The backend extracts rule-based features.
5. The backend scores the URL and builds explanations.
6. The popup displays the risk level, trust score, phishing probability, and reasons.

## Local Development Boundary

The MVP runs locally. The extension calls `http://127.0.0.1:8000`, so no production server or external threat intelligence API is required.

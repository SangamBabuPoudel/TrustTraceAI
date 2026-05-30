# TrustTrace AI Architecture

TrustTrace AI starts as a local browser extension plus FastAPI backend.

## Components

- Chrome extension popup: reads the active tab URL and displays the analysis result.
- FastAPI backend: exposes local analysis endpoints for the extension.
- Threat intelligence placeholder layer: reserves PhishTank, OpenPhish, Google Safe Browsing, URLhaus, and VirusTotal checks for future integrations.
- Reputation and legitimacy layer: verifies official trusted brand domains and local high-reputation domains.
- Deep analysis layer: runs local spoofing, TLD, subdomain, and lookalike checks, with placeholders for ML, RDAP, Tranco, URLScan, and certificate reputation.
- URL feature extractor: turns a URL into simple security signals.
- Risk scoring engine: converts signals into a risk level, phishing probability, and trust score.
- Explanation engine: converts detected signals into beginner-readable reasons.
- ML workspace: reserved for future datasets, notebooks, training, and saved models.

## MVP Flow

1. The user opens the extension popup.
2. The popup reads the active browser tab URL.
3. The popup sends URL, page, form, or selected message data to the local API.
4. The backend checks threat-intel placeholders, reputation/legitimacy, and deep local signals.
5. The backend suppresses weak false-positive signals on official or high-reputation domains.
6. The backend scores strong evidence such as fake brand domains, credential harvesting, sender impersonation, or link mismatch.
7. The popup displays risk, trust score, reasons, trust signals, confidence, and grouped evidence.

## Multi-Layer URL Pipeline

1. Layer 1: Known threat intelligence placeholders for future PhishTank, OpenPhish, Google Safe Browsing, URLhaus, and VirusTotal integrations.
2. Layer 2: Reputation and legitimacy checks for official brand domains, high-reputation domains, Tranco, RDAP/domain age, URLScan, and certificate reputation placeholders.
3. Layer 3: ML and deep analysis placeholders plus local homoglyph, brand spoofing, suspicious TLD, subdomain, and lookalike checks.

## Local Development Boundary

The MVP runs locally. The extension calls `http://127.0.0.1:8000`, so no production server or external threat intelligence API is required.

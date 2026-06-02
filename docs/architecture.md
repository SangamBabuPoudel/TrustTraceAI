# TrustTrace AI Architecture

TrustTrace AI starts as a local browser extension plus FastAPI backend.

## Components

- Chrome extension popup: reads the active tab URL and displays the analysis result.
- Chrome extension service worker: checks navigations with `/api/analyze-url` before or during page load.
- Universal Link Intelligence content script: extracts visible links, annotates search results, and supplies page-wide link lists to the popup.
- Warning interstitial: blocks high-risk destinations and lets users go back or proceed for the current session.
- Caution banner: warns on medium-risk destinations after the page loads.
- FastAPI backend: exposes local analysis endpoints for the extension.
- Threat intelligence layer: checks a local MVP known-bad blocklist and reserves PhishTank, OpenPhish, Google Safe Browsing, URLhaus, VirusTotal, and host feed integrations for later.
- Reputation and legitimacy layer: verifies official trusted brand domains and local high-reputation domains.
- Deep analysis layer: runs local homoglyph, punycode, typosquatting, entropy, TLD, IP-hostname, subdomain, and lookalike checks, with placeholders for ML, RDAP, Tranco, URLScan, and certificate reputation.
- URL feature extractor: turns a URL into simple security signals.
- Risk scoring engine: converts signals into a risk level, phishing probability, and trust score.
- Explanation engine: converts detected signals into beginner-readable reasons.
- ML workspace: reserved for future datasets, notebooks, training, and saved models.

## MVP Flow

1. The user opens the extension popup.
2. The popup reads the active browser tab URL.
3. The popup sends URL, page, form, or selected message data to the local API.
4. The backend checks the local known-bad blocklist, threat-intel placeholders, reputation/legitimacy, and deep local signals.
5. The backend suppresses weak false-positive signals on official or high-reputation domains.
6. The backend scores strong evidence such as fake brand domains, credential harvesting, sender impersonation, or link mismatch.
7. The popup displays risk, trust score, reasons, trust signals, confidence, and grouped evidence.

## Pre-Visit Protection Flow

1. The Manifest V3 service worker listens for top-level HTTP/HTTPS navigation.
2. Localhost, extension pages, file URLs, browser URLs, mailto links, and phone links are ignored.
3. The service worker calls `POST /api/analyze-url` with the destination URL only.
4. High-risk results redirect the tab to `warning.html`.
5. Medium-risk results allow the page to load and inject a yellow caution banner.
6. Proceed Anyway stores a temporary session bypass for the exact URL.
7. High-risk URLs/domains are cached locally so repeat visits warn faster.

## Universal Link Intelligence Flow

1. On Google, Bing, DuckDuckGo, and Yahoo result pages, the content script extracts visible organic result links.
2. Each result URL is sent through the service worker to `POST /api/analyze-url`.
3. The page receives a small TrustTrace badge: Trusted, Low, Caution, High Risk, or Unknown.
4. On any normal webpage, the popup can request visible links from the content script with `TRUSTTRACE_EXTRACT_VISIBLE_LINKS`.
5. The popup scans unique visible URLs with limited concurrency and shows totals plus the riskiest links.
6. High-risk clicks are still handled by the existing pre-visit warning system; link scanning does not navigate automatically.

## Multi-Layer URL Pipeline

1. Layer 1: Local MVP known-bad blocklist plus placeholders for future PhishTank, OpenPhish, Google Safe Browsing, URLhaus, VirusTotal, and host feed integrations.
2. Layer 2: Reputation and legitimacy checks for official brand domains, high-reputation domains, Tranco, RDAP/domain age, URLScan, and certificate reputation placeholders.
3. Layer 3: ML and deep analysis placeholders plus local homoglyph, punycode, typosquatting, entropy, brand spoofing, suspicious TLD, IP hostname, subdomain, and lookalike checks.

Known-bad blocklist matches are instant high-risk evidence. Official trusted domains suppress weak signals such as normal forms, hidden inputs, and ordinary login wording unless stronger evidence appears.

## Local Development Boundary

The MVP runs locally. The extension calls `http://127.0.0.1:8000`, so no production server or external threat intelligence API is required.

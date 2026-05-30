# TrustTrace AI Roadmap

## Phase 1: Clean MVP Foundation

- Create the browser extension shell.
- Create the FastAPI backend.
- Add URL analysis with simple rule-based detection.
- Return explainable reasons for each risk signal.
- Document architecture, API design, privacy, and threat model.

## Phase 2: Browser Page Analysis

- Add MVP page content scanning for visible webpage text.
- Combine URL risk and content risk into one explainable score.
- Add MVP fake login form detection.
- Detect suspicious login forms.
- Identify password fields on insecure pages.
- Flag visual impersonation patterns.
- Add content-script based page scanning.

## Phase 3: Email and Message Safety

- Add MVP email/message threat detection from selected or visible text.
- Detect sender impersonation and brand/domain mismatches.
- Detect suspicious links and display-text destination mismatches.
- Track repeated similar messages locally using message hashes.
- Analyze pasted emails or messages.
- Detect scam language, urgency, payment pressure, and impersonation.
- Add explainable message risk results.

## Phase 3.5: Reputation And Legitimacy Pipeline

- Add known threat-intelligence placeholder layer.
- Add official domain verification and high-reputation domain checks.
- Reduce false positives on legitimate trusted sites.
- Add deep-analysis placeholders for URL ML, RDAP/domain age, Tranco, URLScan, and certificate reputation.

## Phase 4: OCR Screenshot Scam Analysis

- Allow users to upload screenshots.
- Extract visible text with OCR.
- Analyze scam indicators in the extracted text.

## Phase 5: Machine Learning

- Collect safe training datasets.
- Train baseline phishing URL models.
- Compare model results with rule-based detection.
- Add explainability for model-assisted predictions.

## Phase 6: Threat Intelligence Integrations

- Add optional threat intelligence APIs.
- Integrate PhishTank, OpenPhish cached feeds, Google Safe Browsing, URLhaus, and VirusTotal.
- Add Tranco rank, RDAP/domain age, URLScan.io, and certificate reputation checks.
- Cache results responsibly.
- Keep user privacy controls clear and explicit.

## Phase 7: Product Hardening

- Add tests, logging, and error monitoring.
- Improve extension UX.
- Add settings for privacy and analysis modes.
- Prepare packaging and deployment documentation.

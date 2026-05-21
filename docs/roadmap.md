# TrustTrace AI Roadmap

## Phase 1: Clean MVP Foundation

- Create the browser extension shell.
- Create the FastAPI backend.
- Add URL analysis with simple rule-based detection.
- Return explainable reasons for each risk signal.
- Document architecture, API design, privacy, and threat model.

## Phase 2: Browser Page Analysis

- Detect suspicious login forms.
- Identify password fields on insecure pages.
- Flag visual impersonation patterns.
- Add content-script based page scanning.

## Phase 3: Email and Message Safety

- Analyze pasted emails or messages.
- Detect scam language, urgency, payment pressure, and impersonation.
- Add explainable message risk results.

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
- Cache results responsibly.
- Keep user privacy controls clear and explicit.

## Phase 7: Product Hardening

- Add tests, logging, and error monitoring.
- Improve extension UX.
- Add settings for privacy and analysis modes.
- Prepare packaging and deployment documentation.

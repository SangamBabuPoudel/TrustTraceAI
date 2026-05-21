# Privacy Design

TrustTrace AI should be privacy-first by default.

## MVP Principles

- Local-first analysis: the browser extension calls a backend running on the user's machine.
- Minimal data: the MVP sends only the active tab URL for URL analysis.
- No external threat APIs: the MVP does not send URLs to third-party services.
- No account system: the MVP does not require user identity.
- No tracking: the MVP does not include analytics, ads, or behavioral tracking.

## Future Privacy Requirements

- Make external integrations optional and clearly labeled.
- Avoid storing raw browsing history.
- Prefer local or anonymized processing when possible.
- Give users clear controls for screenshot, email, and page-content analysis.
- Document what data is processed before adding each new feature.

# Privacy Design

TrustTrace AI should be privacy-first by default.

## MVP Principles

- Local-first analysis: the browser extension calls a backend running on the user's machine.
- Minimal data: website scans send the active tab URL, visible page text, and form metadata needed for local analysis.
- User-controlled message scans use selected text first, or visible page text only when no text is selected.
- When multiple visible message cards are detected, TrustTrace AI chooses one primary message and lets the user switch candidates.
- Nearby message warnings use lightweight browser-side previews and short snippets; they are not included in the main scan unless the user chooses one.
- TrustTrace AI does not automatically scan a full mailbox or background email content.
- No external threat APIs: the MVP does not send URLs to third-party services.
- Reputation, threat-intelligence, RDAP, Tranco, URLScan, certificate, and ML checks are local placeholders only in MVP 6.5.
- No account system: the MVP does not require user identity.
- No tracking: the MVP does not include analytics, ads, or behavioral tracking.

## Message Scan Storage

Repeated message detection uses a local SQLite database at `backend/trusttrace.db`.

- TrustTrace AI does not store full message bodies.
- It stores a SHA-256 hash made from normalized message text, sender, subject, and link hrefs.
- It stores only short metadata: sender, subject, source URL, short normalized preview, risk level, phishing probability, timestamps, and scan count.
- This storage stays on the user's machine during local MVP development.

## Reputation Checks

- Official domain verification uses a local trusted-domain list.
- High-reputation decisions use a local MVP allowlist for testing.
- No URLs are sent to PhishTank, OpenPhish, Google Safe Browsing, URLhaus, VirusTotal, Tranco, RDAP, URLScan, or certificate reputation services yet.

## Future Privacy Requirements

- Make external integrations optional and clearly labeled.
- Avoid storing raw browsing history.
- Prefer local or anonymized processing when possible.
- Give users clear controls for screenshot, email, and page-content analysis.
- Document what data is processed before adding each new feature.

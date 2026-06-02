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
- Local threat intelligence uses a small built-in MVP blocklist and does not fetch remote feeds.
- Reputation, threat-intelligence, RDAP, Tranco, URLScan, certificate, and ML checks are local placeholders only in the MVP pipeline.
- No account system: the MVP does not require user identity.
- No tracking: the MVP does not include analytics, ads, or behavioral tracking.
- Pre-visit protection sends only the destination URL to the local backend. Page content is not collected for pre-visit warnings.
- Link scanning sends only visible link URLs plus lightweight link text/context. It does not collect search query text, cookies, passwords, hidden form values, or full page text for link-only scans.
- Search result annotation scans visible result URLs only and avoids navigation/sidebar links where possible.
- Attack Explanation Mode is generated locally from existing risk signals and does not call an external AI model or API.

## Message Scan Storage

Repeated message detection uses a local SQLite database at `backend/trusttrace.db`.

- TrustTrace AI does not store full message bodies.
- It stores a SHA-256 hash made from normalized message text, sender, subject, and link hrefs.
- It stores only short metadata: sender, subject, source URL, short normalized preview, risk level, phishing probability, timestamps, and scan count.
- This storage stays on the user's machine during local MVP development.

## Reputation Checks

- Official domain verification uses a local trusted-domain list.
- High-reputation decisions use a local MVP allowlist for testing.
- Known-bad decisions use a local MVP blocklist for testing.
- Deep URL heuristics run locally for homoglyphs, punycode, typosquatting, entropy, suspicious TLDs, and suspicious domain structure.
- No URLs are sent to PhishTank, OpenPhish, Google Safe Browsing, URLhaus, VirusTotal, Tranco, RDAP, URLScan, or certificate reputation services yet.

## Pre-Visit Cache And Bypass

- High-risk pre-visit detections are cached locally in Chrome storage with URL, hostname, risk score, reasons, and timestamp.
- Proceed Anyway stores a temporary session allow decision for the exact URL only.
- The bypass is not a permanent whitelist.

## Universal Link Intelligence

- Page-wide link scans are user-controlled from the popup.
- Search result badges are URL-only annotations for visible results.
- Email/message pages can provide visible links for link scanning, but full mailbox scanning is not performed.
- High-risk link clicks are handled by the existing pre-visit warning page rather than a separate blocking system.

## Attack Explanation Mode

- Explanations are derived from already-computed local signals.
- No additional personal data is collected to create attack explanations.
- No prompt, page text, email text, or URL is sent to an external AI provider for MVP explanations.

## Future Privacy Requirements

- Make external integrations optional and clearly labeled.
- Avoid storing raw browsing history.
- Prefer local or anonymized processing when possible.
- Give users clear controls for screenshot, email, and page-content analysis.
- Document what data is processed before adding each new feature.

# Threat Model

TrustTrace AI focuses on browser security risks that target everyday users.

## Primary Threats

- Phishing websites that imitate trusted brands.
- Fake login forms that steal usernames, passwords, or MFA codes.
- Scam links sent through email, SMS, chat, or social media.
- Sender impersonation using free email providers, lookalike domains, or phone numbers claiming to be trusted companies.
- Repeated similar scam messages that may indicate a phishing campaign.
- URLs that hide their destination with IP addresses, long paths, `@` symbols, confusing subdomains, or deceptive keywords.
- Brand impersonation outside official domains, such as fake Apple, OpenAI, Claude, Gemini, Google, PayPal, or bank login pages.
- Dark patterns that pressure users into unsafe actions.
- Screenshot-based scams that ask users to scan QR codes, call fake support numbers, or enter credentials.

## MVP Risks Covered

The MVP covers URL-level phishing indicators, visible page content, fake login forms, and user-controlled email/message text scans. It does not inspect screenshots, files, downloads, full mailboxes, cookies, or network traffic.

MVP 6.5 adds a reputation and legitimacy layer to reduce false positives on official trusted domains. Brand names, hidden inputs, normal forms, and ordinary login wording are not enough by themselves to mark an official high-reputation site as suspicious.

## Trust Boundaries

- Browser extension: has access to the current tab URL when the popup runs.
- Browser extension: only scans selected or visible message text when the user clicks Scan Email/Message.
- Local backend: receives user-controlled scan payloads and returns rule-based analysis.
- External services: not used in the MVP.
- Threat-intelligence, domain reputation, and ML integrations are placeholders only until explicitly configured in a future phase.

## Security Considerations

- The API should stay local during MVP development.
- Future remote deployments should add authentication, rate limiting, logging controls, and stricter CORS.
- Future content analysis should avoid collecting sensitive page data unless the user explicitly requests it.

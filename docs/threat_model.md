# Threat Model

TrustTrace AI focuses on common browser-based phishing and scam risks.

## Threats Covered

| Threat | How TrustTrace AI responds |
|---|---|
| Phishing URLs | URL scoring, local blocklist, domain heuristics, warning page. |
| Brand impersonation | Official domain verification and brand-outside-domain checks. |
| Fake login forms | Password/email fields, suspicious submit text, form action checks. |
| Suspicious email/message links | User-controlled message scan and link mismatch analysis. |
| Sender impersonation | Free-email provider and claimed-brand/domain mismatch checks. |
| Urgency/social engineering | Detects pressure language such as urgent, suspended, locked, final warning. |
| Typosquatting/lookalikes | Detects punycode, homoglyphs, repeated letters, and similar brand domains. |
| HTTP credential risks | Flags HTTP pages with account/login/payment/password behavior. |
| Repeated scam campaigns | Uses local message hashes to identify repeated similar messages. |
| Risky search/page links | Annotates search results and scans visible links on any page. |
| Local protection awareness | Summarizes local-only security counters in the Personal Security Report Card. |
| Clipboard abuse | Detects suspicious copied URLs, OTP/code paste risks, wallet addresses, recovery phrases, credential-like text, and copy-value mismatch behavior. |

## Attack Explanation Mode

Attack Explanation Mode converts signals into educational guidance:

- What type of attack this may be.
- How the attack works.
- What the user should avoid doing.
- A safer action.

This is rule-based explainability, not an external AI model.

## Trust Boundaries

- Chrome extension: active tab URL, visible page text when scanning, visible links, and user-selected message text.
- MV3 service worker: destination URL checks for navigation protection.
- Local backend: receives scan payloads and returns rule-based analysis.
- SQLite database: stores repeated-message hashes and short metadata.
- External services: not used in the MVP.

## Limitations

- TrustTrace AI does not inspect downloads, files, or network traffic.
- It does not scan QR codes or screenshots yet.
- It does not use real-time external threat intelligence yet.
- It does not use a trained ML phishing classifier yet.
- Search engine page layouts can change and may require annotation maintenance.
- The report card is summary-only and should not be interpreted as complete browsing telemetry.
- Clipboard Guardian is not continuous monitoring; it only reads clipboard text after user action.
- A low-risk result does not guarantee a site is safe; it means the MVP checks did not find strong indicators.

## Safety Notes

This project is intended for portfolio demonstration and local security education. It should not be used as a sole production defense without additional testing, telemetry, external threat intelligence, and operational safeguards.

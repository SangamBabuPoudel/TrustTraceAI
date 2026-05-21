# Threat Model

TrustTrace AI focuses on browser security risks that target everyday users.

## Primary Threats

- Phishing websites that imitate trusted brands.
- Fake login forms that steal usernames, passwords, or MFA codes.
- Scam links sent through email, SMS, chat, or social media.
- URLs that hide their destination with IP addresses, long paths, `@` symbols, confusing subdomains, or deceptive keywords.
- Dark patterns that pressure users into unsafe actions.
- Screenshot-based scams that ask users to scan QR codes, call fake support numbers, or enter credentials.

## MVP Risks Covered

The first MVP covers URL-level phishing indicators. It does not inspect page content, emails, screenshots, files, downloads, or network traffic yet.

## Trust Boundaries

- Browser extension: has access to the current tab URL when the popup runs.
- Local backend: receives the URL and returns a rule-based analysis.
- External services: not used in the MVP.

## Security Considerations

- The API should stay local during MVP development.
- Future remote deployments should add authentication, rate limiting, logging controls, and stricter CORS.
- Future content analysis should avoid collecting sensitive page data unless the user explicitly requests it.

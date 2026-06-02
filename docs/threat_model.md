# Threat Model

TrustTrace AI focuses on browser security risks that target everyday users.

## Primary Threats

- Phishing websites that imitate trusted brands.
- Fake login forms that steal usernames, passwords, or MFA codes.
- Scam links sent through email, SMS, chat, or social media.
- Sender impersonation using free email providers, lookalike domains, or phone numbers claiming to be trusted companies.
- Repeated similar scam messages that may indicate a phishing campaign.
- URLs that hide their destination with IP addresses, long paths, `@` symbols, confusing subdomains, or deceptive keywords.
- URLs using punycode, homoglyphs, typosquatting, suspicious TLDs, high-entropy domains, or login/security prefixes.
- Brand impersonation outside official domains, such as fake Apple, OpenAI, Claude, Gemini, Google, PayPal, or bank login pages.
- High-risk links clicked before the user opens the popup.
- Search results or ordinary webpages that include risky links alongside safe links.
- Dark patterns that pressure users into unsafe actions.
- Screenshot-based scams that ask users to scan QR codes, call fake support numbers, or enter credentials.

## MVP Risks Covered

The MVP covers URL-level phishing indicators, visible page content, fake login forms, and user-controlled email/message text scans. It does not inspect screenshots, files, downloads, full mailboxes, cookies, or network traffic.

MVP 6.5 adds a reputation and legitimacy layer to reduce false positives on official trusted domains. Brand names, hidden inputs, normal forms, and ordinary login wording are not enough by themselves to mark an official high-reputation site as suspicious.

MVP 7 adds pre-visit protection. High-risk URLs are blocked with an interstitial, medium-risk URLs get a caution banner, and low-risk URLs open normally.

MVP 8 adds local threat intelligence and deep URL heuristics. A local known-bad blocklist is treated as instant high-risk evidence for testing. Deep checks detect homoglyphs, punycode, typosquatting, suspicious TLDs, entropy, IP hostnames, and fake brand domains while official trusted domains suppress weak false-positive signals.

MVP 8 also adds Universal Link Intelligence. Search result annotation warns beside visible results, and popup-driven page-wide link scanning summarizes visible links on normal webpages, message pages, blogs, shopping pages, and school sites.

MVP 9 adds Attack Explanation Mode. It classifies likely attack patterns such as credential phishing, brand impersonation, lookalike domains, insecure credential collection, suspicious redirection, urgency pressure, known-bad URLs, and repeated scam campaigns.

## Trust Boundaries

- Browser extension: has access to the current tab URL when the popup runs.
- Browser extension service worker: checks destination URLs during top-level navigation.
- Browser extension: only scans selected or visible message text when the user clicks Scan Email/Message.
- Browser extension: scans visible link URLs only when annotating search results or when the user clicks Scan Links on This Page.
- Local backend: generates attack explanations from existing signals without external AI calls.
- Local backend: receives user-controlled scan payloads and returns rule-based analysis.
- External services: not used in the MVP.
- External threat-intelligence, domain reputation, and ML integrations are placeholders only until explicitly configured in a future phase.

## Security Considerations

- The API should stay local during MVP development.
- Future remote deployments should add authentication, rate limiting, logging controls, and stricter CORS.
- Future content analysis should avoid collecting sensitive page data unless the user explicitly requests it.

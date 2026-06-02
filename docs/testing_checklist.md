# Testing Checklist

Use this checklist before recording a demo or submitting the project.

## Backend

- [ ] Start backend at `http://127.0.0.1:8000`.
- [ ] Confirm `GET /health` returns `{ "status": "ok" }`.
- [ ] Run `python3 -B -m compileall backend/app`.

## Extension

- [ ] Reload unpacked extension in `chrome://extensions`.
- [ ] Confirm popup opens without console errors.
- [ ] Run `node --check extension/background.js`.
- [ ] Run `node --check extension/content.js`.
- [ ] Run `node --check extension/popup.js`.
- [ ] Run `node --check extension/warning.js`.

## Official Websites

- [ ] Scan `https://www.apple.com`.
- [ ] Scan `https://openai.com`.
- [ ] Confirm low risk and high trust score.
- [ ] Confirm no brand impersonation warning.

## Fake Phishing Links

- [ ] Open `extension/test-previsit-links.html`.
- [ ] Click fake Apple phishing link.
- [ ] Confirm high-risk warning page appears.
- [ ] Confirm Proceed Anyway bypass works only for the current session.

## Fake Login Page

- [ ] Open `extension/test-phishing.html`.
- [ ] Scan with popup.
- [ ] Confirm page content and form signals appear.
- [ ] Confirm high risk for urgent password/account verification form.

## Scam Message Page

- [ ] Open `extension/test-scam-message.html`.
- [ ] Enter `google.security.alert@gmail.com`.
- [ ] Scan Email/Message.
- [ ] Confirm sender, message, and link signals.
- [ ] Scan again and confirm repeat count increases.

## Universal Link Scan

- [ ] Open `extension/test-universal-links.html`.
- [ ] Click Scan Links on This Page.
- [ ] Confirm progress appears.
- [ ] Confirm summary counts for trusted, caution, high risk, and unknown.
- [ ] Confirm top risky links show reasons and Copy URL buttons.

## Search Annotation

- [ ] Open a Google search results page.
- [ ] Confirm TrustTrace badges appear beside or below result titles.
- [ ] Confirm badge text is readable and not mirrored.
- [ ] Repeat on Bing, DuckDuckGo, or Yahoo if available.

## Warning Page And Caution Banner

- [ ] Confirm high-risk URLs open `warning.html`.
- [ ] Confirm medium-risk pages show yellow caution banner.
- [ ] Confirm warning page includes attack explanation.

## Attack Explanation Mode

- [ ] Open `extension/test-attack-explanations.html`.
- [ ] Scan fake Apple/OpenAI links.
- [ ] Confirm credential phishing or brand impersonation explanations.
- [ ] Scan typo/lookalike domain.
- [ ] Confirm typosquatting/lookalike explanation.
- [ ] Scan HTTP password form page.
- [ ] Confirm insecure credential collection explanation.

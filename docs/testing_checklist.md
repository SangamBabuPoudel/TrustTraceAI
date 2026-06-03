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
- [ ] Run `node --check extension/demoScenarios.js`.
- [ ] Run `node --check extension/demo.js`.

## Demo Mode

- [ ] Open the popup and click Run Demo Scan.
- [ ] Confirm demo cards appear and say “Demo result — no private data scanned.”
- [ ] Confirm scenarios cover trusted official site, fake phishing URL, visual clone, scam message, Clipboard Guardian, Universal Link Intelligence, HTTP caution, and report card.
- [ ] Click Copy Demo Summary and confirm summary text copies.
- [ ] Click Open Demo Pages and confirm local demo page links appear.
- [ ] Open `http://127.0.0.1:5500/extension/demo.html` and confirm the static dashboard renders.
- [ ] Confirm running Demo Mode does not change Security Report Card counters.

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

## Personal Security Report Card

- [ ] Open the popup and confirm Security Report appears.
- [ ] Run a page scan and confirm URL/page counters increase.
- [ ] Trigger a high-risk warning and confirm high-risk blocks increase.
- [ ] Trigger a medium-risk page and confirm caution warnings increase.
- [ ] Run Scan Links on This Page and confirm link scan counters increase.
- [ ] Scan a scam message and confirm suspicious message counters increase.
- [ ] Scan the same scam message twice and confirm repeated scam warning counter increases.
- [ ] Click Reset Local Stats and confirm counters reset after confirmation.

## Clipboard Guardian Mode

- [ ] Open `extension/test-clipboard-guardian.html`.
- [ ] Confirm Clipboard Guardian is off by default.
- [ ] Turn Clipboard Guardian on.
- [ ] Copy the suspicious URL and click Scan Clipboard Now.
- [ ] Confirm suspicious URL warning appears.
- [ ] Copy the wallet mismatch button and confirm page warning appears.
- [ ] Copy/sample scan OTP text and confirm OTP/security-code warning appears.
- [ ] Scan recovery phrase/private key text and confirm high-risk warning appears.
- [ ] Copy official Apple URL and confirm low-risk or safe URL handling.
- [ ] Confirm report-card clipboard counters increase without storing raw text.

## Visual Clone Intelligence

- [ ] Open `extension/test-visual-clone.html`.
- [ ] Scan with the popup.
- [ ] Confirm Visual Clone Intelligence panel appears.
- [ ] Confirm claimed brands include Apple, Google, and OpenAI/ChatGPT signals.
- [ ] Confirm high risk due to branded login forms on localhost.
- [ ] Confirm attack explanation mentions visual brand cloning or fake login page.
- [ ] Confirm no screenshots, image binaries, or canvas pixels are collected.

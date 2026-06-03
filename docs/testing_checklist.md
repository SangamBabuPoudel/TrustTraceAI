# Testing Checklist

Use this checklist before recording a demo, submitting the project, or making a release-style commit.

## Environment Setup

- [ ] Backend is running at `http://127.0.0.1:8000`.
- [ ] `GET /health` returns `{ "status": "ok" }`.
- [ ] Chrome Developer Mode is enabled in `chrome://extensions`.
- [ ] TrustTrace AI extension is reloaded after the latest code changes.
- [ ] Local test server is running from the repository root with `python3 -m http.server 5500`.
- [ ] Local regression dashboard opens at `http://127.0.0.1:5500/extension/test-regression-dashboard.html`.

## Official Trusted Domains

Test:

- [ ] `https://www.apple.com`
- [ ] `https://support.apple.com`
- [ ] `https://openai.com`
- [ ] `https://chatgpt.com`
- [ ] `https://claude.ai`
- [ ] `https://gemini.google.com`
- [ ] `https://www.youtube.com`
- [ ] `https://www.verizon.com/shop/online/free-cell-phones/apple/`

Expected:

- Low Risk.
- High trust score.
- No false Visual Clone Intelligence warning.
- No false brand impersonation warning.
- Official/trusted context signals may appear.

## Fake Phishing URLs

Test:

- [ ] `http://apple-login-security.example.com/verify`
- [ ] `https://openai-login-verify.example.com/password`
- [ ] `https://claude-security-login.example.com`
- [ ] `https://gemini-google-verify-account.xyz/login`
- [ ] `https://gooogle-login.example.com`

Expected:

- High Risk or Caution depending signal strength.
- Fake brand, typosquatting, lookalike, or impersonation reasons appear.
- URLs with trust score `<= 30` trigger the warning page through pre-visit protection.

## Pre-Visit Warning Page

- [ ] Open `extension/test-previsit-links.html`.
- [ ] Click a high-risk fake link.
- [ ] Confirm `warning.html` appears.
- [ ] Confirm Go Back to Safety works.
- [ ] Confirm Proceed Anyway navigates to the original URL.
- [ ] Confirm Proceed Anyway creates only a session bypass, not a permanent allowlist.

## Medium-Risk Caution Banner

- [ ] Test a medium-risk HTTP, shortened, or suspicious link.
- [ ] Confirm the page loads without redirecting to `warning.html`.
- [ ] Confirm yellow caution banner appears.
- [ ] Confirm Dismiss button removes the banner.

## Page Content Scanning

- [ ] Open `extension/test-phishing.html`.
- [ ] Scan with the popup.
- [ ] Confirm urgent language is detected.
- [ ] Confirm account-threat language is detected.
- [ ] Confirm credential language is detected.

## Fake Login Form Detection

- [ ] Open a fake login page with email and password fields.
- [ ] Confirm form signals are shown.
- [ ] Confirm password field is detected.
- [ ] Confirm suspicious submit text is detected.
- [ ] Confirm high risk when suspicious page content and credential form context exist together.

## Email/Message Threat Detection

- [ ] Open `extension/test-scam-message.html`.
- [ ] Enter `google.security.alert@gmail.com` as sender.
- [ ] Click Scan Email/Message.
- [ ] Confirm sender impersonation is detected.
- [ ] Confirm urgent credential language is detected.
- [ ] Confirm suspicious links are detected.
- [ ] Scan the same message twice.
- [ ] Confirm repeat count increases.

## Universal Link Intelligence

- [ ] Open `extension/test-universal-links.html`.
- [ ] Click Scan Links on This Page.
- [ ] Confirm safe official links are trusted.
- [ ] Confirm fake links are High Risk or Caution.
- [ ] Confirm scan summary counts are reasonable.
- [ ] Confirm top risky links are shown with reasons.

## Search Result Annotation

- [ ] Open Google search for `apple login`.
- [ ] Confirm TrustTrace badges are visible beside or below result titles.
- [ ] Confirm official links are trusted.
- [ ] Confirm badge text is readable and not flipped or mirrored.

## Clipboard Guardian

- [ ] Open `extension/test-clipboard-guardian.html`.
- [ ] Confirm Clipboard Guardian is off by default.
- [ ] Turn Clipboard Guardian on.
- [ ] Copy suspicious URL and click Scan Clipboard Now.
- [ ] Confirm suspicious URL is detected.
- [ ] Click wallet mismatch copy button.
- [ ] Confirm wallet mismatch warning appears.
- [ ] Confirm OTP/security-code prompt warning appears.
- [ ] Confirm recovery phrase/private key warning appears.
- [ ] Copy safe Apple URL and confirm low-risk or safe handling.
- [ ] Confirm raw clipboard text is not stored.

## Visual Clone Intelligence

- [ ] Open `extension/test-visual-clone.html`.
- [ ] Scan with the popup.
- [ ] Confirm fake branded login clone is High Risk.
- [ ] Confirm Visual Clone Intelligence panel appears.
- [ ] Confirm visual clone signals are shown.
- [ ] Confirm official Apple pages are not falsely flagged.
- [ ] Confirm Verizon Apple product page is not falsely flagged.

## Attack Explanation Mode

- [ ] Scan a fake phishing URL or fake login page.
- [ ] Confirm attack type is shown.
- [ ] Confirm summary is shown.
- [ ] Confirm What to Avoid guidance is shown.
- [ ] Confirm Safer Action guidance is shown.
- [ ] Scan a safe page and confirm calm/no strong attack pattern explanation.

## Security Report Card

- [ ] Run a URL/page scan and confirm scan counters increase.
- [ ] Trigger a high-risk warning and confirm high-risk block count increases.
- [ ] Trigger a caution banner and confirm caution count increases.
- [ ] Run Scan Links on This Page and confirm link scan counters increase.
- [ ] Scan a suspicious message and confirm suspicious message count increases.
- [ ] Confirm no sensitive content is stored.
- [ ] Click Reset Local Stats and confirm counters reset after confirmation.

## Demo Mode

- [ ] Open the popup and click Run Demo Scan.
- [ ] Confirm demo cards render.
- [ ] Confirm demo cards are clearly labeled as demo results.
- [ ] Confirm Demo Mode does not change Security Report Card counters.
- [ ] Click Copy Demo Summary and confirm summary text copies.
- [ ] Click Open Demo Pages and confirm local demo page links appear.
- [ ] Open `http://127.0.0.1:5500/extension/demo.html` and confirm static dashboard renders.

## Offline Behavior

- [ ] Stop the backend server.
- [ ] Open the popup and run a scan.
- [ ] Confirm popup shows Backend unavailable.
- [ ] Reload a search page.
- [ ] Confirm search badges show Unknown/Offline if annotation runs.
- [ ] Confirm page does not break.

## Validation Commands

- [ ] Run `python3 -B -m compileall backend/app`.
- [ ] Run `node --check extension/background.js`.
- [ ] Run `node --check extension/content.js`.
- [ ] Run `node --check extension/popup.js`.
- [ ] Run `node --check extension/warning.js`.
- [ ] Run `node --check extension/clipboardGuardian.js`.
- [ ] Run `node --check extension/securityStats.js`.
- [ ] Run `node --check extension/demoScenarios.js`.
- [ ] Run `node --check extension/demo.js`.
- [ ] Run `python3 backend/tests/regression_api_tests.py` while backend is running.

## Regression Pass/Fail Table

| Feature | Test URL/Page | Expected Result | Actual Result | Pass/Fail | Notes |
|---|---|---|---|---|---|
| Official trusted domain | `https://www.apple.com` | Low Risk, high trust, no impersonation warning |  |  |  |
| Official trusted domain | `https://support.apple.com` | Low Risk, official Apple trust signal |  |  |  |
| Official trusted domain | `https://openai.com` | Low Risk, official OpenAI trust signal |  |  |  |
| Trusted commerce context | `https://www.verizon.com/shop/online/free-cell-phones/apple/` | Low Risk, no Apple clone warning |  |  |  |
| Fake phishing URL | `http://apple-login-security.example.com/verify` | High Risk, warning eligible |  |  |  |
| Fake phishing URL | `https://openai-login-verify.example.com/password` | High Risk, fake brand/login reasons |  |  |  |
| Typosquatting | `https://gooogle-login.example.com` | Caution/High Risk, lookalike reason |  |  |  |
| Pre-visit warning | `extension/test-previsit-links.html` | High-risk links open warning page |  |  |  |
| Caution banner | Medium-risk HTTP/shortened link | Yellow banner appears and dismisses |  |  |  |
| Page content scan | `extension/test-phishing.html` | Urgent/account/credential language detected |  |  |  |
| Fake login form | `extension/test-phishing.html` | Form signals and high risk |  |  |  |
| Message scan | `extension/test-scam-message.html` | Sender, message, link, repeat signals |  |  |  |
| Universal links | `extension/test-universal-links.html` | Summary and top risky links |  |  |  |
| Search annotation | Google search `apple login` | Badges visible and readable |  |  |  |
| Clipboard Guardian | `extension/test-clipboard-guardian.html` | URL, wallet, OTP, recovery warnings |  |  |  |
| Visual Clone | `extension/test-visual-clone.html` | High Risk visual clone signals |  |  |  |
| Attack Explanation | Fake phishing scan | Attack type, avoid guidance, safer action |  |  |  |
| Report Card | Popup Security Report | Counters update/reset, no sensitive content |  |  |  |
| Demo Mode | Popup Demo Mode | Demo cards render and are labeled |  |  |  |
| Offline behavior | Backend stopped | Offline messaging, page does not break |  |  |  |

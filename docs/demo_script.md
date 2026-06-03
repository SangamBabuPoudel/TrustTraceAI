# Demo Script

Use this 3-5 minute script for a portfolio, internship, or technical interview walkthrough.

## Setup

Start the backend:

```bash
cd backend
source .venv/bin/activate
python3 -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Start the local test server from the repo root:

```bash
python3 -m http.server 5500
```

Reload the unpacked extension in `chrome://extensions`.

## Talk Track

1. Introduce the project.
   - “TrustTrace AI is an explainable Chrome security extension that detects phishing URLs, fake login forms, scam messages, suspicious links, and brand impersonation.”
   - “The current MVP is rule-based and local; external APIs and ML are future-ready placeholders.”

2. Run Demo Mode.
   - Open the popup and click Run Demo Scan.
   - Show the sample cards for trusted official domains, fake phishing URLs, visual clone pages, scam messages, Clipboard Guardian, Universal Link Intelligence, attack explanations, and the Security Report Card.
   - Point out the label: “Demo result — no private data scanned.”

3. Open Demo Pages.
   - Click Open Demo Pages in the popup.
   - Mention the local server command: `python3 -m http.server 5500`.
   - Optionally open `http://127.0.0.1:5500/extension/demo.html` for a full-screen portfolio dashboard.

4. Show a safe official site.
   - Open `https://www.apple.com` or `https://openai.com`.
   - Open the popup and show high trust score and official-domain trust signals.

5. Show a fake phishing link.
   - Open `http://127.0.0.1:5500/extension/test-previsit-links.html`.
   - Click the fake Apple or OpenAI link.
   - Show the high-risk warning page and attack explanation.

6. Show fake login form detection.
   - Open `http://127.0.0.1:5500/extension/test-phishing.html`.
   - Open the popup and scan the page.
   - Point out password field detection, urgent content, trust score, and attack explanation.

7. Show email/message scanning.
   - Open `http://127.0.0.1:5500/extension/test-scam-message.html`.
   - Enter `google.security.alert@gmail.com` as sender.
   - Click Scan Email/Message.
   - Show sender impersonation, message signals, suspicious link, and repeated-message count after scanning twice.

8. Show Universal Link Intelligence.
   - Open `http://127.0.0.1:5500/extension/test-universal-links.html`.
   - Click Scan Links on This Page.
   - Show total scanned links and top risky links.

9. Show search result annotation.
   - Open a Google/Bing/DuckDuckGo/Yahoo search page.
   - Point out TrustTrace badges beside visible search results.

10. Show the Personal Security Report Card.
   - Open the popup Security Report section.
   - Show URL scans, high-risk blocks, caution warnings, suspicious messages, high-risk links, repeated scams, and most common attack type.
   - Mention that these are local-only summary counts with a reset option.

11. Show Clipboard Guardian.
   - Open `http://127.0.0.1:5500/extension/test-clipboard-guardian.html`.
   - Turn Clipboard Guardian on.
   - Copy the suspicious URL and click Scan Clipboard Now.
   - Show that raw clipboard text is not stored and non-URL content is analyzed locally.

12. Show Visual Clone Intelligence.
   - Open `http://127.0.0.1:5500/extension/test-visual-clone.html`.
   - Scan the page from the popup.
   - Show claimed brands, visual clone score, branded login form signals, and visual brand cloning attack explanation.
   - Mention that this uses DOM metadata only, not screenshots or image files.

13. Show final QA coverage.
   - Open `http://127.0.0.1:5500/extension/test-regression-dashboard.html`.
   - Explain that the dashboard links to all local feature fixtures and safe/risky regression URLs.
   - Mention `docs/testing_checklist.md`, `docs/qa_commands.md`, and `backend/tests/regression_api_tests.py`.

14. Close with architecture.
   - “The extension talks to FastAPI, FastAPI runs a multi-layer local scoring pipeline, and the UI renders warnings, banners, badges, and explanations.”

## Closing Line

“The goal was to build a portfolio-grade security product prototype that is explainable, privacy-conscious, and extensible toward real threat intelligence and ML.”

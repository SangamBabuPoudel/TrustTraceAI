# QA Commands

Use these commands for final TrustTrace AI validation.

## Start Backend

```bash
cd ~/Desktop/TrustTraceAI/backend
source .venv/bin/activate
python3 -m uvicorn app.main:app --reload
```

## Start Local Server

```bash
cd ~/Desktop/TrustTraceAI
python3 -m http.server 5500
```

## Run Backend Syntax Validation

```bash
cd ~/Desktop/TrustTraceAI
python3 -B -m compileall backend/app
```

## Run JavaScript Validation

```bash
cd ~/Desktop/TrustTraceAI
node --check extension/background.js
node --check extension/content.js
node --check extension/popup.js
node --check extension/warning.js
node --check extension/clipboardGuardian.js
node --check extension/securityStats.js
node --check extension/demoScenarios.js
node --check extension/demo.js
```

## Run API Regression Script

Start the backend first, then run:

```bash
cd ~/Desktop/TrustTraceAI
python3 backend/tests/regression_api_tests.py
```

## Open Local Regression Dashboard

Start the local server first, then open:

```text
http://127.0.0.1:5500/extension/test-regression-dashboard.html
```

## Suggested Full QA Order

1. Start backend.
2. Start local server.
3. Reload unpacked Chrome extension.
4. Run backend compile validation.
5. Run JavaScript validation.
6. Run API regression script.
7. Open local regression dashboard.
8. Complete `docs/testing_checklist.md`.

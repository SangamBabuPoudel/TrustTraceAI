# Privacy Design

TrustTrace AI is designed around minimal collection, local analysis, and user-controlled scans.

## Principles

- Local-first: the extension calls a backend running on the user's machine.
- Minimal data: each workflow sends only the data needed for that analysis.
- User control: message scanning happens only when the user clicks Scan Email/Message.
- No hidden mailbox scanning: TrustTrace AI does not connect to Gmail, Outlook, or other provider APIs.
- No external threat APIs in the MVP: current threat intelligence integrations are placeholders.
- No external AI model in the MVP: Attack Explanation Mode is rule-based and local.

## What Is Collected

| Workflow | Data used |
|---|---|
| URL scan | Current URL. |
| Pre-visit warning | Destination URL only. |
| Page scan | URL, visible text, page title, form metadata. |
| Visual Clone Intelligence | DOM metadata such as title, headings, favicon/logo URLs, image alt/title/src metadata, button text, input labels, brand-like text, and layout hints. |
| Link scan | Visible link URLs, link text, hostname, lightweight surrounding context. |
| Search annotation | Visible result URLs only. |
| Message scan | Selected or visible message text, optional sender input, visible links. |
| Repeated message detection | Hash and short metadata, not full message body. |
| Security Report Card | Local summary counters and attack type counts. |
| Clipboard Guardian | User-initiated clipboard text scan; non-URL text is local-only. |

## What Is Not Collected

- Passwords.
- Cookies.
- Hidden form values.
- Full mailbox data.
- Background email content.
- Browser history.
- Full URL paths for report-card metrics.
- Search query text for annotation.
- Raw clipboard text or clipboard history.
- Screenshots, image binaries, canvas pixels, or visual recordings.
- API keys in frontend code.

## Repeated Message Storage

Repeated scam/campaign detection uses local SQLite storage at `backend/trusttrace.db`.

Stored:

- SHA-256 message hash.
- Sender.
- Subject.
- Source URL.
- Short normalized preview.
- Risk level.
- Phishing probability.
- First/last seen timestamps.
- Scan count.

Not stored:

- Full message bodies.
- Passwords.
- Cookies.
- Private mailbox data.

## Pre-Visit Protection

Pre-visit protection sends only the destination URL to the local backend. Page content is not collected before navigation. If a URL is high risk, the extension shows `warning.html`. If the user clicks Proceed Anyway, the exact URL is allowed for the current browser session only.

## Personal Security Report Card

The report card uses `chrome.storage.local` to store local summary counts on this browser. It tracks counts such as total scans, high-risk blocks, caution banners, suspicious messages, high-risk links, fake login forms, repeated scam warnings, and attack type counts.

It does not store full message text, passwords, cookies, form values, personal account data, or full browsing history. The popup includes Reset Local Stats so the user can clear report-card metrics at any time.

## Clipboard Guardian Mode

- Clipboard Guardian is off by default.
- The user must manually turn it on.
- Clipboard text is read only when the user clicks Scan Clipboard Now.
- Raw clipboard text is not stored.
- Clipboard history is not stored.
- Non-URL clipboard text is analyzed locally and is not sent to the backend.
- Clipboard URLs may be sent to `/api/analyze-url` only after the user clicks Scan Clipboard Now.
- The feature detects suspicious URLs, OTP/security codes, wallet addresses, recovery phrases, private keys, credential-like text, and copy-value mismatches.

## Visual Clone Intelligence

- Visual Clone Intelligence is metadata-only.
- It uses DOM-visible brand claims and layout clues to detect fake branded login pages.
- It collects image URLs and alt/title/class/id metadata, but not image files or pixels.
- It does not take screenshots.
- It does not run screenshot similarity or computer-vision ML in the MVP.
- Official brand domains are checked before clone warnings are applied to reduce false positives.

## External Integrations

Future integrations such as Google Safe Browsing, PhishTank, URLHaus, RDAP, Tranco, URLScan, and ML classifiers should remain optional, backend-only, clearly documented, and privacy reviewed before use.

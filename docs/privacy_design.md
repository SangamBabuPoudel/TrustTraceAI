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
| Personal Adaptive Trust | Opt-in local domain-level scan counts, feedback counts, last risk level, last trust score, and bounded adjustment for this browser only. |
| Future community reputation | Placeholder design for thresholded domain-level global signals; not implemented as a reporting pipeline today. |

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
- Full URL paths, query strings, page text, clipboard content, emails/messages, form values, tokens, or browsing history for Personal Adaptive Trust.
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

## Personal Adaptive Trust

Personal Adaptive Trust is off until the user turns it on in the popup. When enabled, it stores minimal local trust metadata for sanitized domains only. A private URL such as `https://example.com/private/page?token=abc` is reduced to `example.com` before learning data is stored.

Stored:

- Domain.
- Total scans.
- Safe, caution, and high-risk scan counts.
- Last risk level and last trust score.
- User trusted/suspicious/false-positive feedback counts.
- Last seen timestamp.
- Small learned trust adjustment.

Not stored:

- Full URLs, paths, query strings, or tokens.
- Page text.
- Passwords or form values.
- Emails, messages, or mailbox content.
- Clipboard text.
- Cookies or session data.
- Full browsing history.

Personal Adaptive Trust cannot override strong phishing indicators. Known-bad URLs, high-confidence visual clones, credential phishing, typosquatting, suspicious sender identity, clipboard/recovery phrase risks, and other strong high-risk evidence remain high risk even if a user has trusted a domain before.

## Personal Adaptive Trust Vs Community Reputation

Personal learning affects only the current user's browser. One user complaint, trusted mark, suspicious mark, or false-positive report does not change TrustTrace detection for everyone.

Community reputation is a future/global design and is not implemented as a cloud reporting pipeline in this MVP. Any future global signal should:

- Require many independent reports before affecting global trust.
- Rate-limit and deduplicate reports.
- Store only sanitized domain-level data.
- Avoid private URL paths, query strings, page text, passwords, emails, clipboard text, cookies, tokens, and browsing history.
- Be weighted lower than official-domain reputation and verified threat intelligence.
- Never override known malicious feeds or strong phishing indicators.

Abuse risks include attackers trying to mass-mark phishing domains as safe, competitors falsely reporting legitimate domains as suspicious, and users accidentally marking the wrong domain. That is why one report should remain local-only.

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

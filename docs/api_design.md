# API Design

## Health Check

`GET /health`

Response:

```json
{
  "status": "ok"
}
```

## Analyze URL

`POST /api/analyze-url`

Request:

```json
{
  "url": "https://example.com"
}
```

Response:

```json
{
  "url": "https://example.com",
  "risk_level": "low",
  "phishing_probability": 0.0,
  "trust_score": 100,
  "reasons": []
}
```

### Risk Levels

- `low`: few or no suspicious rule-based indicators.
- `medium`: several warning signs are present.
- `high`: strong phishing indicators are present.

### MVP Detection Signals

- HTTP instead of HTTPS.
- Long URL length.
- Suspicious keywords such as `login`, `verify`, `account`, `secure`, `update`, `bank`, `password`, and `refund`.
- IP address in the URL hostname.
- Excessive hyphens in the hostname.
- Too many subdomains.
- `@` symbol in the URL.
- Known URL shorteners such as `bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `ow.ly`, `is.gd`, `buff.ly`, and `rebrand.ly`.
- Suspicious top-level domains such as `.xyz`, `.top`, `.click`, `.work`, `.zip`, `.country`, `.stream`, `.gq`, `.tk`, and `.ml`.
- Brand impersonation keywords such as `paypal`, `amazon`, `apple`, `microsoft`, `google`, `netflix`, `facebook`, `instagram`, `bankofamerica`, `chase`, and `wells-fargo`.
- Encoded characters such as `%2F`.
- Multiple slashes after the hostname.
- Unusually long query strings.

### Scoring Model

The MVP scoring engine uses transparent rule weights. Each detected signal adds risk points. The final score is capped at `100`.

- `phishing_probability` is the capped risk score divided by `100`.
- `trust_score` is `100` minus the capped risk score.
- `risk_level` is `low` below `30`, `medium` from `30` to `59`, and `high` at `60` or above.

Local development URLs skip this scoring model during MVP testing.

### Local Development URLs

During MVP testing, local development hosts are treated as safe development URLs and skip phishing risk scoring. This includes `localhost`, `127.0.0.1`, `0.0.0.0`, and `::1`.

Example response:

```json
{
  "url": "http://127.0.0.1:8000/health",
  "risk_level": "low",
  "phishing_probability": 0.0,
  "trust_score": 100,
  "reasons": ["Local development URL detected; phishing risk scoring skipped."]
}
```

## Example Test URLs

### Safe URL

```json
{
  "url": "https://example.com"
}
```

Expected result: `low` risk, high trust score, and no obvious phishing indicators.

### Suspicious Brand Impersonation URL

```json
{
  "url": "http://paypal-secure-login.verify-account.security.example.com/update"
}
```

Expected result: `high` risk because it uses HTTP, includes phishing keywords, contains a brand name, has multiple subdomains, and uses hyphenated impersonation-style wording.

### Shortened URL

```json
{
  "url": "https://bit.ly/3SuspiciousLink"
}
```

Expected result: elevated risk because known URL shorteners can hide the final destination.

### Suspicious TLD URL

```json
{
  "url": "https://account-verify-example.xyz/login"
}
```

Expected result: elevated risk because the URL includes phishing keywords, hyphens, and a suspicious top-level domain.

### Localhost URL

```json
{
  "url": "http://localhost:8000"
}
```

Expected result: `low` risk with risk scoring skipped for local MVP development.

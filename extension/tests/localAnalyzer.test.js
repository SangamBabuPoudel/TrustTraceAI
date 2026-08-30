// Run with: node --test extension/tests/localAnalyzer.test.js

const assert = require("node:assert/strict");
const test = require("node:test");

require("../localAnalyzer.js");

const analyzer = globalThis.TrustTraceLocalAnalyzer;

const SAFE_URLS = [
  "https://microsoft.com",
  "https://www.microsoft.com",
  "https://login.microsoftonline.com",
  "https://device.login.microsoftonline.com",
  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
  "https://login.microsoftonline.com/example/saml2",
  "https://office.com",
  "https://outlook.office.com",
  "https://myprofile.microsoft.com",
  "https://aadcdn.msftauth.net",
  "https://aadcdn.msauth.net",
  "https://myprofile.microsoft.com",
  "https://accounts.google.com",
  "https://accounts.google.com/signin",
  "https://github.com/login",
  "https://apple.com",
  "https://appleid.apple.com",
  "https://duosecurity.com",
  "https://api-12345.duosecurity.com",
  "https://okta.com",
  "https://auth0.com",
  "https://cdn.auth0.com",
  "https://cloudflareaccess.com",
  "https://www.cloudflare.com",
  "https://device.login.microsoftonline.com/common/oauth2/authorize",
  "https://appleid.apple.com/auth/authorize",
  "https://gist.github.com",
  "https://api-98765.duosecurity.com/frame/web/v1/auth"
];

const HIGH_RISK_LOOKALIKE_URLS = [
  "https://login.microsoftonline.com.security-check.example",
  "https://device.login.microsoftonline.com.authentication.example",
  "https://microsoftonline.com.login.example.com",
  "https://login-microsoftonline.example.com",
  "https://microsoft-authenticator-verify.xyz/login",
  "https://microsoft-login-security.example.com/verify",
  "https://accounts.google.com.verify-session.example",
  "https://accounts.google.com.verify.example.com",
  "https://accounts-google-login.example.com",
  "https://google-authenticator-verify.example.com",
  "https://github.com.security-session.example",
  "https://github.com.login.example.com",
  "https://github-login-security.example.com",
  "https://appleid.apple.com.secure-account.example",
  "https://appleid-verify-login.example.com",
  "https://secure-google-login.xyz/account",
  "https://usf.edu.login.example.com",
  "https://usf-login-security.example.com",
  "https://okta-login-security.example.com",
  "https://duo-security-login.example.com",
  "https://example.com/redirect?next=https%3A%2F%2Flogin.microsoftonline.com",
  "https://login.microsoftonline.com.security-check.example",
  "https://device.login.microsoftonline.com.authentication.example",
  "https://accounts.google.com.verify-session.example",
  "https://github.com.security-session.example",
  "https://appleid.apple.com.secure-account.example",
  "https://microsoft.com@account-security.example/login",
  "http://192.0.2.10/login",
  "http://203.0.113.25/account/password",
  "https://xn--pple-43d.example/login",
  "https://аррӏе.example/login",
  "https://login.paypal.security.example/verify",
  "https://secure.microsoft.example/redirect?continue=https%3A%2F%2Flogin.microsoftonline.com",
  "https://apple-login-security.test/verify",
  "https://openai-login-verify.invalid/password",
  "https://github-security-verify.example/login",
  "https://paypal-account-update.example/secure"
];

const CAUTION_NOT_TRUSTED_URLS = [
  "http://example.com/login",
  "https://unknown-login.example/account",
  "https://signin.example/verify",
  "https://a.b.c.d.e.example.com/login",
  "https://bit.ly/example",
  "https://tinyurl.com/signin"
];

test("localAnalyzer is available", () => {
  assert.equal(typeof analyzer?.analyzeUrl, "function");
});

test("official authentication and brand domains are not high risk", () => {
  for (const url of SAFE_URLS) {
    const result = analyzer.analyzeUrl(url);
    assert.notEqual(result.risk_level, "high", `${url} should not be high risk`);
    assert.ok(result.trust_score >= 85, `${url} should keep trust_score >= 85, got ${result.trust_score}`);
    assert.ok(
      result.reputation?.is_official_auth_provider ||
        result.reputation?.is_official_brand_domain ||
        result.reputation?.is_high_reputation_domain,
      `${url} should have official/high-reputation metadata`
    );
  }
});

test("lookalike and deceptive auth domains remain high risk", () => {
  for (const url of HIGH_RISK_LOOKALIKE_URLS) {
    const result = analyzer.analyzeUrl(url);
    assert.equal(result.risk_level, "high", `${url} should be high risk`);
    assert.ok(result.trust_score <= 30, `${url} should keep trust_score <= 30, got ${result.trust_score}`);
  }
});

test("brand mentions outside the real parent domain are not treated as official", () => {
  const boundaryCases = [
    "https://microsoft.com.security-alert.example.com",
    "https://accounts.google.com.evil.example",
    "https://github.com.login.example.com",
    "https://apple.com.verify.example"
  ];

  for (const url of boundaryCases) {
    const result = analyzer.analyzeUrl(url);
    assert.equal(result.reputation?.is_official_auth_provider, false, `${url} should not be an official auth provider`);
    assert.equal(result.reputation?.is_official_brand_domain, false, `${url} should not be an official brand domain`);
    assert.notEqual(result.risk_level, "low", `${url} should not be low risk`);
  }
});

test("HTTP, raw IP, and unknown auth URLs are not falsely trusted", () => {
  for (const url of CAUTION_NOT_TRUSTED_URLS) {
    const result = analyzer.analyzeUrl(url);
    assert.ok(result.trust_score <= 80, `${url} should not look highly trusted, got ${result.trust_score}`);
    assert.equal(result.reputation?.is_official_auth_provider, false, `${url} should not be an official auth provider`);
  }
});

test("brand text in path or query never creates official trust", () => {
  const brandTextOnlyCases = [
    "https://example.com/apple",
    "https://example.com/login?provider=github",
    "https://example.com/search?q=appleid.apple.com",
    "https://example.com/search?q=github",
    "https://shop.example/products/microsoft-office"
  ];

  for (const url of brandTextOnlyCases) {
    const result = analyzer.analyzeUrl(url);
    assert.equal(result.reputation?.is_official_auth_provider, false, `${url} should not be an official auth provider`);
    assert.equal(result.reputation?.is_official_brand_domain, false, `${url} should not be an official brand domain`);
    assert.ok(result.trust_score < 95, `${url} should not receive official-domain trust, got ${result.trust_score}`);
  }
});

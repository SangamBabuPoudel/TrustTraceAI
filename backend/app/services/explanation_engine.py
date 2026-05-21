from app.services.url_feature_extractor import UrlFeatures


def build_explanations(features: UrlFeatures) -> list[str]:
    if features.is_local_development:
        return ["Local development URL detected; phishing risk scoring skipped."]

    reasons: list[str] = []

    if features.uses_http:
        reasons.append("The URL uses HTTP instead of encrypted HTTPS.")
    if features.is_long_url:
        reasons.append(
            f"The URL is unusually long at {features.length} characters."
        )
    if features.suspicious_keywords:
        keywords = ", ".join(features.suspicious_keywords)
        reasons.append(
            f"The URL contains phishing-related keyword(s): {keywords}."
        )
    if features.has_ip_address:
        reasons.append(
            f"The URL uses the IP address {features.hostname} instead of a normal domain name."
        )
    if features.has_excessive_hyphens:
        reasons.append(
            f"The domain contains {features.hyphen_count} hyphens, which can be used to imitate trusted domains."
        )
    if features.has_many_subdomains:
        reasons.append(
            f"The URL contains {features.subdomain_count} subdomains, which can mimic trusted sites."
        )
    if features.has_at_symbol:
        reasons.append(
            "The URL contains an @ symbol, which can hide the real destination."
        )
    if features.is_url_shortener:
        reasons.append(
            f"The domain {features.hostname} is a known URL shortener, which can hide the final destination."
        )
    if features.suspicious_tld:
        reasons.append(
            f"The domain uses the suspicious top-level domain {features.suspicious_tld}."
        )
    if features.brand_impersonation_keywords:
        brands = ", ".join(features.brand_impersonation_keywords)
        reasons.append(
            f"The URL contains brand name(s) often used in impersonation scams: {brands}."
        )
    if features.has_encoded_characters:
        reasons.append(
            "The URL contains encoded characters, which can obscure suspicious text."
        )
    if features.has_multiple_slashes:
        reasons.append(
            "The URL contains multiple slashes after the domain, which can make the destination harder to read."
        )
    if features.has_long_query_string:
        reasons.append(
            f"The URL has a long query string at {features.query_length} characters."
        )

    if not reasons:
        reasons.append("No obvious phishing indicators were found by the MVP rule checks.")

    return reasons

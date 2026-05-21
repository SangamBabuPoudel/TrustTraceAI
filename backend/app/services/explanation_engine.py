from app.services.url_feature_extractor import UrlFeatures


def build_explanations(features: UrlFeatures) -> list[str]:
    reasons: list[str] = []

    if features.uses_http:
        reasons.append("The URL uses HTTP instead of encrypted HTTPS.")
    if features.is_long_url:
        reasons.append("The URL is unusually long, which can hide suspicious details.")
    if features.suspicious_keywords:
        keywords = ", ".join(features.suspicious_keywords)
        reasons.append(f"The URL contains suspicious keyword(s): {keywords}.")
    if features.has_ip_address:
        reasons.append("The URL uses an IP address instead of a normal domain name.")
    if features.has_excessive_hyphens:
        reasons.append("The domain contains an unusually high number of hyphens.")
    if features.has_many_subdomains:
        reasons.append("The URL contains many subdomains, which can mimic trusted sites.")
    if features.has_at_symbol:
        reasons.append("The URL contains an @ symbol, which can hide the real destination.")

    if not reasons:
        reasons.append("No obvious phishing indicators were found by the MVP rule checks.")

    return reasons

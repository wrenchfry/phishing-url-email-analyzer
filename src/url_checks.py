from urllib.parse import urlparse


def check_url(url):
    findings = []
    score = 0
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if parsed.scheme.lower() != "https":
        findings.append("URL does not use HTTPS")
        score += 2

    if not domain:
        findings.append("Could not read the domain")
        score += 1

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "findings": findings,
    }


def risk_label(score):
    if score >= 5:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"

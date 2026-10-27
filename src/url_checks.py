import ipaddress
import re
from urllib.parse import parse_qsl, unquote, urlparse

import tldextract

from signals import signal


SHORTENED_URL_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "is.gd",
]

REDIRECT_PARAMETER_NAMES = {"continue", "next", "redirect", "redirect_uri", "return", "target", "url"}
EXPLICIT_ATTACHMENT_EXTENSIONS = {".exe", ".js", ".jse", ".msi", ".scr", ".vbs", ".bat", ".cmd", ".ps1"}
EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def registrable_domain(hostname):
    hostname = hostname.lower().rstrip(".")
    if not hostname or is_ip_address(hostname):
        return hostname
    extracted = EXTRACTOR(hostname)
    if not extracted.domain or not extracted.suffix:
        return hostname
    return f"{extracted.domain}.{extracted.suffix}"


def subdomain_count(domain):
    if is_ip_address(domain):
        return 0
    extracted = EXTRACTOR(domain)
    return len([part for part in extracted.subdomain.split(".") if part])


def _has_encoded_redirect(parsed):
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if name.lower() in REDIRECT_PARAMETER_NAMES and re.match(r"https?://", unquote(value), re.IGNORECASE):
            return True
    return False


def check_url(url):
    signals = []
    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower().rstrip(".")

    if parsed.scheme.lower() != "https":
        signals.append(
            signal(
                "URL transport", "medium", "URL does not use HTTPS", url, "Do not submit information through this link."
            )
        )

    if not domain:
        signals.append(
            signal(
                "URL structure",
                "medium",
                "Could not read the destination domain",
                url,
                "Verify the link with the sender through a trusted channel.",
            )
        )
    elif is_ip_address(domain):
        signals.append(
            signal(
                "URL structure",
                "high",
                "URL uses an IP address instead of a named domain",
                domain,
                "Do not open the link; use the organisation's known website instead.",
            )
        )

    if registrable_domain(domain) in SHORTENED_URL_DOMAINS:
        signals.append(
            signal(
                "URL structure",
                "medium",
                "URL uses a shortened-link service",
                domain,
                "Preview or verify the final destination before opening it.",
            )
        )

    if subdomain_count(domain) >= 3:
        signals.append(
            signal(
                "URL structure",
                "medium",
                "URL has many subdomains",
                domain,
                "Check the registrable domain, not the words at the start of the link.",
            )
        )

    if parsed.username:
        signals.append(
            signal(
                "URL structure",
                "high",
                "URL contains a user-info '@' trick",
                parsed.netloc,
                "Trust the hostname after '@', not the text before it.",
            )
        )

    try:
        port = parsed.port
    except ValueError:
        port = None
        signals.append(
            signal(
                "URL structure", "medium", "URL contains an invalid port", parsed.netloc, "Do not open malformed links."
            )
        )
    if port and port not in {80, 443}:
        signals.append(
            signal(
                "URL structure",
                "medium",
                "URL uses an unusual network port",
                str(port),
                "Verify the destination before opening it.",
            )
        )

    if domain.startswith("xn--") or ".xn--" in domain:
        signals.append(
            signal(
                "URL identity",
                "high",
                "Domain uses punycode and may imitate another name",
                domain,
                "Type the known website address yourself instead of using the link.",
            )
        )
    elif any(ord(character) > 127 for character in domain):
        signals.append(
            signal(
                "URL identity",
                "high",
                "Domain contains non-ASCII characters that may be lookalikes",
                domain,
                "Type the known website address yourself instead of using the link.",
            )
        )

    if "%" in url:
        signals.append(
            signal(
                "URL structure",
                "low",
                "URL contains percent-encoded characters",
                url,
                "Inspect the decoded destination before trusting the link.",
            )
        )
    if _has_encoded_redirect(parsed):
        signals.append(
            signal(
                "URL redirects",
                "medium",
                "URL contains a redirect target in its query string",
                url,
                "This tool did not follow the redirect; verify the final destination separately.",
            )
        )

    return {
        "url": url,
        "domain": domain,
        "registrable_domain": registrable_domain(domain),
        "signals": signals,
    }

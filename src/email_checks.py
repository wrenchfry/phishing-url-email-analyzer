import re
from pathlib import Path

from signals import signal
from url_checks import registrable_domain


URGENCY_WORDS = ["urgent", "today", "locked", "suspended", "unusual activity", "losing access", "before the end of the day"]
BRAND_DOMAINS = {"microsoft": "microsoft.com", "google": "google.com", "paypal": "paypal.com", "amazon": "amazon.com", "apple": "apple.com", "netflix": "netflix.com"}
RISKY_ATTACHMENT_EXTENSIONS = {".exe", ".js", ".jse", ".msi", ".scr", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".iso"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz"}


def get_sender_address(text):
    match = re.search(r"^From:.*<([^>\s]+)>", text, flags=re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def get_subject(text):
    match = re.search(r"^Subject:\s*(.+)$", text, flags=re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _domain_from_address(address):
    return address.rsplit("@", 1)[1].lower().rstrip(".") if "@" in address else ""


def _attachment_signals(attachments):
    signals = []
    for attachment in attachments:
        filename = attachment["filename"]
        suffixes = [suffix.lower() for suffix in Path(filename).suffixes]
        last_suffix = suffixes[-1] if suffixes else ""
        if last_suffix in RISKY_ATTACHMENT_EXTENSIONS:
            signals.append(signal("Attachments", "high", "Email includes an executable or script attachment", filename, "Do not open the attachment; submit it to your security team for review."))
        elif last_suffix in ARCHIVE_EXTENSIONS:
            signals.append(signal("Attachments", "medium", "Email includes an archive attachment", filename, "Treat unexpected archives carefully and verify the sender first."))
        if len(suffixes) >= 2 and suffixes[-1] in RISKY_ATTACHMENT_EXTENSIONS:
            signals.append(signal("Attachments", "high", "Attachment uses a double extension that can hide its real type", filename, "Do not open the attachment; submit it to your security team for review."))
    return signals


def check_email_message(message, url_results):
    """Inspect headers and message content without opening links or attachments."""
    signals = []
    headers = message["headers"]
    urgency_matches = [word for word in URGENCY_WORDS if word in message["text"].lower()]
    if urgency_matches:
        signals.append(signal("Social engineering", "medium", "Email uses pressure or urgency language", ", ".join(urgency_matches), "Pause before acting and verify the request through a trusted channel."))

    sender_domain = _domain_from_address(headers["from_address"])
    reply_to_domain = _domain_from_address(headers["reply_to"])
    if sender_domain and reply_to_domain and registrable_domain(sender_domain) != registrable_domain(reply_to_domain):
        signals.append(signal("Sender identity", "high", "Reply-To domain differs from the From domain", f"{sender_domain} -> {reply_to_domain}", "Reply only after confirming the sender through a known contact method."))

    return_path_domain = _domain_from_address(headers["return_path"])
    if sender_domain and return_path_domain and registrable_domain(sender_domain) != registrable_domain(return_path_domain):
        signals.append(signal("Sender identity", "low", "Return-Path domain differs from the From domain", f"{sender_domain} -> {return_path_domain}", "Treat this as context; mailing services can legitimately use a different return path."))

    auth_results = headers["authentication_results"].lower()
    if re.search(r"\b(spf|dkim|dmarc)=fail", auth_results):
        signals.append(signal("Sender authentication", "high", "Authentication header reports a failed SPF, DKIM, or DMARC check", headers["authentication_results"], "Do not trust the sender address without independent verification."))

    display_name = headers["from_display"].lower()
    for brand, expected_domain in BRAND_DOMAINS.items():
        if brand in display_name and sender_domain and registrable_domain(sender_domain) != expected_domain:
            signals.append(signal("Sender identity", "high", "Display name appears to impersonate a known brand", f"{headers['from_display']} <{sender_domain}>", "Use the brand's official website or support channel instead of replying."))
            break

    for result in url_results:
        if sender_domain and result["registrable_domain"] and registrable_domain(sender_domain) != result["registrable_domain"]:
            signals.append(signal("Sender identity", "medium", "Link domain differs from the sender's registrable domain", f"{registrable_domain(sender_domain)} -> {result['registrable_domain']}", "Verify whether the sender normally uses this domain before opening the link."))
            break

    signals.extend(_attachment_signals(message["attachments"]))
    return {"sender": headers["from_address"], "subject": headers["subject"], "signals": signals}


def check_email_text(text, urls=None):
    """Compatibility wrapper for plain-text sample files and simple callers."""
    urls = urls or []
    message = {"text": text, "headers": {"from_address": get_sender_address(text), "from_display": "", "reply_to": "", "return_path": "", "subject": get_subject(text), "authentication_results": ""}, "attachments": []}
    return check_email_message(message, [{"registrable_domain": "", "url": url, "signals": []} for url in urls])

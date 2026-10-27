from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path


def _text_parts(message):
    parts = []
    for part in message.walk():
        if part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() != "text/plain":
            continue
        try:
            parts.append(part.get_content())
        except (LookupError, UnicodeDecodeError):
            payload = part.get_payload(decode=True) or b""
            parts.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(parts)


def _attachments(message):
    attachments = []
    for part in message.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            {
                "filename": part.get_filename() or "unnamed attachment",
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
            }
        )
    return attachments


def parse_eml(path):
    """Read an RFC 5322 email without contacting remote services or opening files."""
    with Path(path).open("rb") as stream:
        message = BytesParser(policy=policy.default).parse(stream)
    from_display, from_address = parseaddr(message.get("From", ""))
    reply_display, reply_address = parseaddr(message.get("Reply-To", ""))
    _, return_path = parseaddr(message.get("Return-Path", ""))
    return {
        "is_eml": True,
        "text": _text_parts(message),
        "headers": {
            "from": message.get("From", ""),
            "from_display": from_display,
            "from_address": from_address,
            "reply_to": reply_address,
            "reply_to_display": reply_display,
            "return_path": return_path,
            "subject": message.get("Subject", ""),
            "authentication_results": message.get("Authentication-Results", ""),
        },
        "attachments": _attachments(message),
    }


def parse_text(path):
    text = Path(path).read_text(encoding="utf-8")
    from_display, from_address = parseaddr(
        next((line[5:].strip() for line in text.splitlines() if line.lower().startswith("from:")), "")
    )
    reply_display, reply_address = parseaddr(
        next((line[9:].strip() for line in text.splitlines() if line.lower().startswith("reply-to:")), "")
    )
    subject = next((line[8:].strip() for line in text.splitlines() if line.lower().startswith("subject:")), "")
    return {
        "is_eml": False,
        "text": text,
        "headers": {
            "from": from_address,
            "from_display": from_display,
            "from_address": from_address,
            "reply_to": reply_address,
            "reply_to_display": reply_display,
            "return_path": "",
            "subject": subject,
            "authentication_results": "",
        },
        "attachments": [],
    }


def read_message(path):
    path = Path(path)
    if path.suffix.lower() == ".eml":
        return parse_eml(path)
    return parse_text(path)

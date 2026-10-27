import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from email_checks import check_email_message


def messages(result):
    return [item["message"] for item in result["signals"]]


def message(headers, attachments=None):
    return {"text": "Hello", "headers": headers, "attachments": attachments or []}


class EmailChecksTest(unittest.TestCase):
    def test_reply_to_mismatch_uses_registrable_domains(self):
        result = check_email_message(
            message(
                {
                    "from_address": "notice@updates.example.co.za",
                    "from_display": "",
                    "reply_to": "help@evil.example",
                    "return_path": "",
                    "subject": "Hello",
                    "authentication_results": "",
                }
            ),
            [],
        )
        self.assertIn("Reply-To domain differs from the From domain", messages(result))

    def test_known_brand_display_name_spoof_is_flagged(self):
        result = check_email_message(
            message(
                {
                    "from_address": "alerts@notice.example",
                    "from_display": "Microsoft Security",
                    "reply_to": "",
                    "return_path": "",
                    "subject": "Hello",
                    "authentication_results": "",
                }
            ),
            [],
        )
        self.assertIn("Display name appears to impersonate a known brand", messages(result))

    def test_authentication_failure_is_flagged(self):
        result = check_email_message(
            message(
                {
                    "from_address": "alerts@example.org",
                    "from_display": "",
                    "reply_to": "",
                    "return_path": "",
                    "subject": "Hello",
                    "authentication_results": "spf=fail smtp.mailfrom=example.org",
                }
            ),
            [],
        )
        self.assertIn("Authentication header reports a failed SPF, DKIM, or DMARC check", messages(result))

    def test_executable_attachment_is_flagged(self):
        headers = {
            "from_address": "alerts@example.org",
            "from_display": "",
            "reply_to": "",
            "return_path": "",
            "subject": "Hello",
            "authentication_results": "",
        }
        result = check_email_message(
            message(
                headers, [{"filename": "invoice.pdf.exe", "content_type": "application/octet-stream", "size_bytes": 12}]
            ),
            [],
        )
        self.assertIn("Email includes an executable or script attachment", messages(result))
        self.assertIn("Attachment uses a double extension that can hide its real type", messages(result))

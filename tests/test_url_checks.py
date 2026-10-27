import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path


sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from email_checks import check_email_message  # noqa: E402
from email_parser import parse_eml  # noqa: E402
from signals import summarize_signals  # noqa: E402
from url_checks import check_url, registrable_domain, subdomain_count  # noqa: E402


def messages(result):
    return [item["message"] for item in result["signals"]]


class UrlChecksTest(unittest.TestCase):
    def test_registrable_domain_handles_country_suffix(self):
        self.assertEqual(registrable_domain("signin.paypal.co.uk"), "paypal.co.uk")

    def test_subdomain_count_uses_public_suffix(self):
        self.assertEqual(subdomain_count("login.secure.example.co.za"), 2)

    def test_safe_training_url_has_no_signals(self):
        result = check_url("https://learning.example.org/security/password-awareness")
        self.assertEqual(result["signals"], [])

    def test_ip_address_is_high_risk(self):
        result = check_url("http://192.168.10.44/login")
        self.assertIn("URL uses an IP address instead of a named domain", messages(result))

    def test_shortened_url_is_flagged(self):
        result = check_url("https://bit.ly/account-restore")
        self.assertIn("URL uses a shortened-link service", messages(result))

    def test_user_info_trick_is_flagged(self):
        result = check_url("https://paypal.com@evil.example/login")
        self.assertIn("URL contains a user-info '@' trick", messages(result))
        self.assertEqual(result["registrable_domain"], "evil.example")

    def test_unusual_port_is_flagged(self):
        result = check_url("https://example.org:8443/login")
        self.assertIn("URL uses an unusual network port", messages(result))

    def test_punycode_is_flagged(self):
        result = check_url("https://xn--pple-43d.example/login")
        self.assertIn("Domain uses punycode and may imitate another name", messages(result))

    def test_encoded_redirect_is_flagged_without_following(self):
        result = check_url("https://example.org/login?next=https%3A%2F%2Fevil.example")
        self.assertIn("URL contains a redirect target in its query string", messages(result))


class EmailChecksTest(unittest.TestCase):
    def test_reply_to_mismatch_uses_registrable_domains(self):
        message = {
            "text": "Hello",
            "headers": {"from_address": "notice@updates.example.co.za", "from_display": "", "reply_to": "help@evil.example", "return_path": "", "subject": "Hello", "authentication_results": ""},
            "attachments": [],
        }
        result = check_email_message(message, [])
        self.assertIn("Reply-To domain differs from the From domain", messages(result))

    def test_known_brand_display_name_spoof_is_flagged(self):
        message = {
            "text": "Hello",
            "headers": {"from_address": "alerts@notice.example", "from_display": "Microsoft Security", "reply_to": "", "return_path": "", "subject": "Hello", "authentication_results": ""},
            "attachments": [],
        }
        result = check_email_message(message, [])
        self.assertIn("Display name appears to impersonate a known brand", messages(result))

    def test_authentication_failure_is_flagged(self):
        message = {
            "text": "Hello",
            "headers": {"from_address": "alerts@example.org", "from_display": "", "reply_to": "", "return_path": "", "subject": "Hello", "authentication_results": "spf=fail smtp.mailfrom=example.org"},
            "attachments": [],
        }
        result = check_email_message(message, [])
        self.assertIn("Authentication header reports a failed SPF, DKIM, or DMARC check", messages(result))

    def test_executable_attachment_is_flagged(self):
        message = {
            "text": "Hello",
            "headers": {"from_address": "alerts@example.org", "from_display": "", "reply_to": "", "return_path": "", "subject": "Hello", "authentication_results": ""},
            "attachments": [{"filename": "invoice.pdf.exe", "content_type": "application/octet-stream", "size_bytes": 12}],
        }
        result = check_email_message(message, [])
        self.assertIn("Email includes an executable or script attachment", messages(result))
        self.assertIn("Attachment uses a double extension that can hide its real type", messages(result))

    def test_eml_parser_collects_headers_and_attachment_without_opening_it(self):
        email = EmailMessage()
        email["From"] = "Billing Team <billing@example.org>"
        email["Reply-To"] = "help@reply.example"
        email["Subject"] = "Invoice"
        email.set_content("See attached invoice.")
        email.add_attachment(b"not executed", maintype="application", subtype="octet-stream", filename="invoice.exe")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.eml"
            path.write_bytes(email.as_bytes())
            result = parse_eml(path)
        self.assertEqual(result["headers"]["from_address"], "billing@example.org")
        self.assertEqual(result["attachments"][0]["filename"], "invoice.exe")

    def test_group_scores_are_capped(self):
        result = summarize_signals([
            {"category": "URL structure", "severity": "high", "message": "one", "evidence": "", "recommendation": "a"},
            {"category": "URL structure", "severity": "high", "message": "two", "evidence": "", "recommendation": "a"},
        ])
        self.assertEqual(result["groups"][0]["capped_score"], 5)
        self.assertEqual(result["overall_risk"], "High")


if __name__ == "__main__":
    unittest.main()

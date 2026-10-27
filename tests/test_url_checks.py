import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from url_checks import check_url, registrable_domain, subdomain_count  # noqa: E402


def messages(result):
    return [item["message"] for item in result["signals"]]


class UrlChecksTest(unittest.TestCase):
    def test_registrable_domain_handles_country_suffix(self):
        self.assertEqual(registrable_domain("signin.paypal.co.uk"), "paypal.co.uk")

    def test_subdomain_count_uses_public_suffix(self):
        self.assertEqual(subdomain_count("login.secure.example.co.za"), 2)

    def test_safe_training_url_has_no_signals(self):
        self.assertEqual(check_url("https://learning.example.org/security/password-awareness")["signals"], [])

    def test_ip_address_is_flagged(self):
        self.assertIn(
            "URL uses an IP address instead of a named domain", messages(check_url("http://192.168.10.44/login"))
        )

    def test_shortened_url_is_flagged(self):
        self.assertIn("URL uses a shortened-link service", messages(check_url("https://bit.ly/account-restore")))

    def test_user_info_trick_is_flagged(self):
        result = check_url("https://paypal.com@evil.example/login")
        self.assertIn("URL contains a user-info '@' trick", messages(result))
        self.assertEqual(result["registrable_domain"], "evil.example")

    def test_unusual_port_is_flagged(self):
        self.assertIn("URL uses an unusual network port", messages(check_url("https://example.org:8443/login")))

    def test_punycode_is_flagged(self):
        self.assertIn(
            "Domain uses punycode and may imitate another name",
            messages(check_url("https://xn--pple-43d.example/login")),
        )

    def test_encoded_redirect_is_flagged_without_following(self):
        result = check_url("https://example.org/login?next=https%3A%2F%2Fevil.example")
        self.assertIn("URL contains a redirect target in its query string", messages(result))

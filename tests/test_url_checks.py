import sys
import unittest
from pathlib import Path


sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from url_checks import check_url, risk_label, subdomain_count  # noqa: E402


class UrlChecksTest(unittest.TestCase):
    def test_safe_training_url_stays_low_risk(self):
        result = check_url("https://learning.example.org/security/password-awareness")

        self.assertEqual(risk_label(result["score"]), "Low")
        self.assertEqual(result["findings"], [])

    def test_ip_address_url_is_flagged(self):
        result = check_url("http://192.168.10.44/login")

        self.assertIn("URL does not use HTTPS", result["findings"])
        self.assertIn("URL uses an IP address instead of a normal domain", result["findings"])
        self.assertEqual(risk_label(result["score"]), "High")

    def test_shortened_url_is_flagged(self):
        result = check_url("https://bit.ly/account-restore")

        self.assertIn("URL uses a shortened link service", result["findings"])
        self.assertEqual(risk_label(result["score"]), "Medium")

    def test_subdomain_count_ignores_normal_domains(self):
        self.assertEqual(subdomain_count("example.org"), 0)
        self.assertEqual(subdomain_count("login.secure.account.example.org"), 3)


if __name__ == "__main__":
    unittest.main()

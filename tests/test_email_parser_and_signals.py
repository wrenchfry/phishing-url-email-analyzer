import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from email_parser import parse_eml  # noqa: E402
from signals import summarize_signals  # noqa: E402


class EmailParserTest(unittest.TestCase):
    def test_parser_collects_headers_and_attachment_without_opening_it(self):
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


class SignalSummaryTest(unittest.TestCase):
    def test_group_scores_are_capped(self):
        result = summarize_signals([
            {"category": "URL structure", "severity": "high", "message": "one", "evidence": "", "recommendation": "a"},
            {"category": "URL structure", "severity": "high", "message": "two", "evidence": "", "recommendation": "a"},
        ])
        self.assertEqual(result["groups"][0]["capped_score"], 5)
        self.assertEqual(result["overall_risk"], "High")

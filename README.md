# Phishing URL and Email Analyzer

This project is a small defensive cybersecurity learning tool for checking suspicious links and email text. The goal is to practise basic phishing triage: extracting URLs, spotting risky patterns, giving a simple risk rating, and writing a short report that a security analyst or user could understand.

## Why I Am Building This

I became interested in phishing analysis after a personal incident where I downloaded software from a site I thought was legitimate: `https://www.hellokittycity.com/`. After running it, I noticed signs that my account/session token access may have been compromised.

That experience made me want to understand how suspicious links, impersonation, downloads, and social engineering can lead to account compromise. This project is my way of turning that mistake into practical cybersecurity learning.

## Planned Features

Current checks include:

- Extract URLs from pasted email text.
- Deduplicate repeated URLs.
- Show the email subject and sender address.
- Check URLs for suspicious words such as `login`, `verify`, `password`, and `free`.
- Detect links that use IP addresses instead of normal domains.
- Detect shortened links such as `bit.ly`.
- Flag URLs with many subdomains.
- Look for urgent or threatening language in email text.
- Compare sender domains with link domains.
- Check simple link text and destination mismatches.
- Generate a markdown report with findings and a risk level.

## What This Project Demonstrates

- Basic security operations triage.
- Introductory phishing and social engineering analysis.
- Indicator extraction from emails and URLs.
- Clear written reporting for non-technical users.
- Awareness of ethical and defensive cybersecurity work.

## Limitations

This tool will not prove that a URL is malicious. It uses simple rule-based checks only, so it can miss real phishing links and it can also flag safe links by mistake.

It does not open suspicious links, download files, collect credentials, scan attachments, or perform offensive testing. The sample emails are for learning and demonstration only.

Future improvements could include checking domain age and using reputation services such as VirusTotal, Google Safe Browsing, URLScan.io, or PhishTank.

## Status

Early learning project. The first version will be built as a Python command-line tool.

## Run

```bash
python src/main.py samples/suspicious_email.txt
```

To write a markdown report:

```bash
python src/main.py samples/suspicious_email.txt --report reports/sample_phishing_analysis.md
```

To run the basic tests:

```bash
python -m unittest discover -s tests
```

## Learning Notes

- [Phishing awareness brief](docs/phishing_awareness_brief.md)
- [Evidence handling notes](docs/evidence_handling_notes.md)

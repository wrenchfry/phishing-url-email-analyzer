# Phishing URL and Email Analyzer

This project is a small defensive cybersecurity learning tool for checking suspicious links and email text. The goal is to practise basic phishing triage: extracting URLs, spotting risky patterns, giving a simple risk rating, and writing a short report that a security analyst or user could understand.

## Why I Am Building This

I became interested in phishing analysis after a personal incident where I downloaded software from a site I thought was legitimate: `https://www.hellokittycity.com/`. After running it, I noticed signs that my account/session token access may have been compromised.

That experience made me want to understand how suspicious links, impersonation, downloads, and social engineering can lead to account compromise. This project is my way of turning that mistake into practical cybersecurity learning.

## Planned Features

- Extract URLs from pasted email text.
- Check URLs for suspicious words such as `login`, `verify`, `password`, and `free`.
- Detect links that use IP addresses instead of normal domains.
- Flag possible brand impersonation when a known brand appears in an unusual domain.
- Look for urgent or threatening language in email text.
- Generate a simple markdown report with findings and a risk level.

## What This Project Demonstrates

- Basic security operations triage.
- Introductory phishing and social engineering analysis.
- Indicator extraction from emails and URLs.
- Clear written reporting for non-technical users.
- Awareness of ethical and defensive cybersecurity work.

## Limitations

This tool will not prove that a URL is malicious. The first version will use simple rule-based checks only. It will not open suspicious links, download files, collect credentials, or perform offensive testing.

Future improvements could include checking domain age and using reputation services such as VirusTotal, Google Safe Browsing, URLScan.io, or PhishTank.

## Status

Early learning project. The first version will be built as a Python command-line tool.

# Phishing Analysis Report

Generated: 2026-10-27 16:52

## Summary

- Overall risk: High
- No URLs or attachments were opened by this tool.

## Email Details

- Subject: Urgent: Your account will be locked today
- Sender: security-alert@account-verify-help.com
- Input format: plain text

## Findings by Category

### URL structure - High risk

- **URL uses a shortened-link service**
  - Evidence: bit.ly
  - Why it matters: Preview or verify the final destination before opening it.
- **URL has many subdomains**
  - Evidence: login.secure.account.verify-help.example.com
  - Why it matters: Check the registrable domain, not the words at the start of the link.
- **URL uses an IP address instead of a named domain**
  - Evidence: 192.168.10.44
  - Why it matters: Do not open the link; use the organisation's known website instead.

### Social engineering - Medium risk

- **Email uses pressure or urgency language**
  - Evidence: urgent, today, locked, suspended, unusual activity, losing access, before the end of the day
  - Why it matters: Pause before acting and verify the request through a trusted channel.

### Sender identity - Medium risk

- **Link domain differs from the sender's registrable domain**
  - Evidence: account-verify-help.com -> bit.ly
  - Why it matters: Verify whether the sender normally uses this domain before opening the link.

### URL transport - Medium risk

- **URL does not use HTTPS**
  - Evidence: http://192.168.10.44/login
  - Why it matters: Do not submit information through this link.

## URLs

### https://account-verify-help.com/login/secure-update

- Registrable domain: account-verify-help.com
- No URL-specific warning signals found.

### https://bit.ly/account-restore

- Registrable domain: bit.ly

### https://login.secure.account.verify-help.example.com/update

- Registrable domain: example.com

### HTTPS://account-verify-help.com/restore-access

- Registrable domain: account-verify-help.com
- No URL-specific warning signals found.

### http://192.168.10.44/login

- Registrable domain: 192.168.10.44

## Recommended Next Steps

- Pause before acting and verify the request through a trusted channel.
- Verify whether the sender normally uses this domain before opening the link.
- Preview or verify the final destination before opening it.
- Check the registrable domain, not the words at the start of the link.
- Do not submit information through this link.
- Do not open the link; use the organisation's known website instead.

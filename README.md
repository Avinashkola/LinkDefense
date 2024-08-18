LinkDefense
LinkDefense is a lightweight JavaScript tool designed to scan and flag suspicious URLs on a webpage. It helps detect potentially harmful links based on various heuristics, including suspicious TLDs, typosquatting, URL IP addresses, etc. The tool is particularly useful for enhancing web security by alerting users to potentially malicious links before they interact with them.

Features
Whitelist Trusted Domains: Ensure well-known, legitimate domains are never flagged as suspicious.
Suspicious TLD Detection: Flag URLs with suspicious top-level domains (TLDs) such as .xyz, .top, and more.
Typosquatting Detection: Identify URLs that closely resemble legitimate domains using Levenshtein distance.
IP Address in URL Detection: Flag URLs that use IP addresses instead of domain names.
Suspicious Pattern Detection: Detect URLs containing suspicious patterns, such as URL-encoded characters.
Shortened URL Detection: Recognize and flag shortened URLs from popular services like bit.ly, t.co, etc.
Protocol Handling: Properly sanitize and check URLs, even if they are missing the http:// or https:// protocol.




Test Cases
LinkDefense includes a suite of test cases to validate its functionality. Below are some of the key test cases:

Valid Legitimate Domain: Ensure that legitimate domains are not marked as suspicious.
Suspicious TLD: Verify that URLs with suspicious TLDs are flagged.
Typosquatting Domain: Test detection of domains that closely resemble legitimate ones.
IP Address in URL: Check that URLs using IP addresses are flagged as suspicious.
URL Containing Suspicious Pattern: Verify that URLs with suspicious patterns (e.g., URL-encoded characters) are flagged.
URL Without Protocol: Ensure URLs missing the http:// or https:// protocol are correctly sanitized and checked.
URL with Subdomain: Confirm that legitimate subdomains are recognized as safe.
Shortened URL: Verify that shortened URLs are flagged as suspicious.

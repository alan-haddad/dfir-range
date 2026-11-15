#!/usr/bin/env python3
"""
Inert-content scan. Fails if generated evidence (or payloads decoded from it)
contains anything that could point at real infrastructure or real organizations:

  * IPv4 addresses outside RFC 5737 documentation ranges and private/loopback ranges
  * domain names outside the reserved .example / .test / .invalid names
  * names of real companies and brands (beyond an explicit allowlist of platform
    identifiers that realistic Windows telemetry requires)

Usage: python3 -I tools/ci/inert_scan.py <dir> [<dir> ...]
"""

import ipaddress
import re
import sys
from pathlib import Path

ALLOWED_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # RFC 5737
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
)]
ALLOWED_SUFFIXES = (".example", ".test", ".invalid")

# Platform identifiers that real Windows telemetry contains. Removed before scanning.
ALLOWLIST_PHRASES = [
    "http://schemas.microsoft.com/win/2004/08/events/event",
    "http://schemas.microsoft.com/windows/2004/02/mit/task",
    "Microsoft-Windows-Sysmon",
    "Microsoft-Windows-Security-Auditing",
    "Microsoft Corporation",
    "Microsoft® Windows® Operating System",
    "Microsoft Windows",  # Authenticode signer of Windows binaries
    "Microsoft Office",
    "Microsoft Graph",
    "Microsoft Azure CLI",
    "Office 365 Exchange Online",
    "Office 365 SharePoint Online",
    "Windows Azure Service Management API",
]

# User-agent strings legitimately name browsers and carry version numbers that look like IPs.
UA_FIELD_RE = re.compile(r'"userAgent"\s*:\s*"[^"]*"')
# Windows registry paths contain the vendor name as a key, e.g. HKCU\Software\Microsoft\Windows.
REGISTRY_RE = re.compile(r"Software\\+Microsoft\\+Windows", re.I)

# Real top-level domains likely to appear by accident. File extensions that are
# not TLDs (exe, dll, ps1, dat ...) are deliberately absent.
REAL_TLDS = set("""
com net org io co us uk de ru cn info biz xyz top online site app dev cloud ai me tv gov edu mil int eu ca au in jp fr it nl br
zip mov link live store shop tech website space club ly gg sh to cc ws
""".split())

BRANDS = [
    "microsoft", "google", "amazon", "aws", "apple", "facebook", "meta", "netflix", "paypal", "docusign", "dropbox",
    "adobe", "salesforce", "zoom", "slack", "cisco", "oracle", "ibm", "intel", "nvidia", "cloudflare", "akamai",
    "okta", "crowdstrike", "sentinelone", "palo alto", "fortinet", "splunk", "github", "gitlab", "twitter", "linkedin",
    "walmart", "fedex", "dhl", "usps", "wells fargo", "citibank", "bank of america", "office365", "office 365",
    "outlook", "onedrive", "sharepoint", "gmail", "yahoo", "chrome", "firefox", "edge browser", "mcafee", "symantec",
    "norton", "kaspersky", "sophos", "mandiant", "proofpoint", "mimecast", "contoso", "fabrikam", "northwind",
]

IP_RE = re.compile(r"(?<![\w.])(\d{1,4})\.(\d{1,4})\.(\d{1,4})\.(\d{1,4})(?![\w.])")
URL_HOST_RE = re.compile(r"[a-z][a-z0-9+.-]*://([^/\s'\"<>?#:]+)", re.I)
EMAIL_HOST_RE = re.compile(r"[\w.+-]+@([a-z0-9.-]+\.[a-z]{2,})", re.I)
FIELD_HOST_RE = re.compile(r"(?:smtp\.mailfrom|header\.from|header\.d)=([a-z0-9.-]+)", re.I)
TOKEN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+([a-z]{2,24}))\b", re.I)


def host_ok(host: str) -> bool:
    host = host.lower().rstrip(".")
    try:
        return any(ipaddress.ip_address(host) in n for n in ALLOWED_NETS)
    except ValueError:
        pass
    return host.endswith(ALLOWED_SUFFIXES)


def scan_text(path: Path, text: str) -> list:
    problems = []
    text = UA_FIELD_RE.sub(" ", text)
    text = REGISTRY_RE.sub(" ", text)
    for phrase in ALLOWLIST_PHRASES:
        text = text.replace(phrase, " ")
    for m in IP_RE.finditer(text):
        # Leading zeros mean octal in numbers-and-dots notation (inet_aton).
        octets = [int(x, 8) if len(x) > 1 and x.startswith("0") and set(x) <= set("01234567") else int(x) for x in m.groups()]
        if any(o > 255 for o in octets):
            continue
        ip = ipaddress.ip_address(".".join(map(str, octets)))
        if not any(ip in n for n in ALLOWED_NETS):
            problems.append(f"{path}: IP outside documentation/private ranges: {ip}")
    hosts = set(URL_HOST_RE.findall(text)) | set(EMAIL_HOST_RE.findall(text)) | set(FIELD_HOST_RE.findall(text))
    for h in hosts:
        if not host_ok(h):
            problems.append(f"{path}: host not under .example/.test/.invalid: {h}")
    for full, tld in TOKEN_RE.findall(text):
        if tld.lower() in REAL_TLDS and not host_ok(full):
            problems.append(f"{path}: token with a real TLD: {full}")
    lower = text.lower()
    for b in BRANDS:
        # Alphanumeric boundaries, so a name inside a random token (e.g. "9aws2") is not a match.
        if re.search(rf"(?<![a-z0-9]){re.escape(b)}(?![a-z0-9])", lower):
            problems.append(f"{path}: real company or brand name: {b}")
    return problems


def main() -> None:
    roots = [Path(p) for p in sys.argv[1:]]
    if not roots:
        raise SystemExit("usage: inert_scan.py <dir> [<dir> ...]")
    problems, files = [], 0
    for root in roots:
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            files += 1
            raw = path.read_bytes()
            text = raw.decode("utf-16", errors="ignore") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", errors="ignore")
            problems += scan_text(path, text)
    for p in problems:
        print("FAIL", p)
    print(f"scanned {files} files: {len(problems)} problem(s)")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()

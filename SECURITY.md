# Security

## Design

- **Static site.** dfir-range has no backend and no third-party requests. CI fails if the built site requests any other origin.
- **Inert evidence.** All evidence is generated, synthetic and inert:
  - no real malware, working payloads or command-and-control;
  - "shellcode" or binaries, where they appear, are placeholder bytes;
  - IP addresses come from RFC 5737 documentation ranges or private ranges;
  - domains use the reserved `.example`, `.test` and `.invalid` names.
- **Fictional names.** Organizations and people are fictional.
- **Scanned on every change.** CI scans every generated bundle, and payloads decoded from it, for real IPs, real domains and real company names.
- **Text rendering.** All evidence is shown as text with `textContent`, never interpreted as HTML.

## Reporting a problem

If you find something that should not be here, such as a real address or domain, a payload that does more than its placeholder purpose, or a real company or person's name, please open a GitHub issue.
- If the issue itself would be harmful to describe publicly, open an issue asking for a private contact instead.
- Please don't include live indicators in public issues.

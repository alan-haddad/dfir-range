# dfir-range

**Free, browser-based practice for SOC analyst and incident response interviews.**

A common technical interview goes like this: the interviewer drops a link to some evidence and says *"go through this and walk me through your thought process."* This range lets you rehearse exactly that, with realistic synthetic evidence that changes with every seed, and debriefs that show what a strong answer sounds like.

**Try it:** https://alan-haddad.github.io/dfir-range/

- Runs entirely in your browser. No account, no install, no tracking.
- Every scenario comes from a seed in the URL, so you can repeat or share it, or roll a new one.
- All evidence is synthetic and inert (see [Safety](#safety)).

---

## Contents

- [Quick start](#quick-start)
- [Troubleshooting](#troubleshooting)
- [The three modes](#the-three-modes)
- [Modules](#modules)
- [Working with your own tools](#working-with-your-own-tools)
- [Run it locally or offline](#run-it-locally-or-offline)
- [Privacy](#privacy)
- [Safety](#safety)
- [Contributing](#contributing)
- [License](#license)

## Quick start

1. Open the site.
2. **New to this?** Start with Learn: Module 01, then 05, then 07. Each one teaches one concept.
3. **Interview next week?** Go straight to **Interview mode**, set a 20-minute timer, and talk through the case out loud. Then answer the structured questions and grade yourself against the rubric.
4. **Five spare minutes?** Do **Drills**: fast recognition reps you can do on a phone.

## Troubleshooting

| Problem | Fix |
|---|---|
| Progress disappeared | Progress lives in this browser's local storage. Private windows and clearing site data erase it. Use **About → Export progress** to keep a copy. |
| The CyberChef link shows "not found" | The offline CyberChef copy is added when the site is deployed. When running from source (`npm run dev`), it isn't there. |
| "Record my walkthrough" is greyed out | Your browser doesn't support in-page audio recording, or the page isn't on `https://` or `localhost`. |
| The page is blank | The site needs JavaScript. Everything runs locally; nothing is sent anywhere. |
| A downloaded `.ps1.txt` or zip is flagged by antivirus | The content is inert text. The script is deliberately saved with a `.txt` extension, but some scanners flag PowerShell download patterns in any file. Allow it for this folder or work in the browser instead. |

## The three modes

**Interview mode.** One case file and one prompt: *"Go through this and walk me through your thought process."*
- **Phase 1:** talk through it out loud. There's an optional timer and an optional local recording, so you can hear yourself.
- **Phase 2:** answer the structured questions an interviewer asks next.
- **Phase 3:** grade yourself against the rubric, read the likely follow-up questions, and optionally build a prompt to paste into an AI assistant of your choice for feedback.

**Learn.** One concept per module, in the same structure every time:
1. Objective.
2. Background: why each step matters and what the tell is.
3. Where the evidence is.
4. Tiered hints.
5. Explain it, in your own words.
6. Check your answer.
7. Debrief: what interviewers listen for, weak, solid and strong answers, follow-ups, common mistakes, and primary-source references. The debrief unlocks after you attempt a question.

**Drills.** Thirty-second recognition reps:
- spot UTF-16LE Base64;
- normalize obfuscated IPs;
- recover XOR keys from a crib;
- ZoneId values;
- event IDs;
- SPF vs DMARC;
- order of volatility;
- double extensions.

## Modules

Modules are tagged **SOC Tier 1**, **SOC Tier 2 / IR**, or both.

| # | Module | Track |
|---|---|---|
| 01 | PowerShell -EncodedCommand | Tier 1, Tier 2 / IR |
| 02 | Obfuscated download cradle | Tier 1, Tier 2 / IR |
| 03 | Single-byte XOR config | Tier 2 / IR |
| 05 | Mark-of-the-Web | Tier 1, Tier 2 / IR |
| 07 | Phishing header analysis | Tier 1, Tier 2 / IR |
| 11 | Containment while preserving evidence | Tier 2 / IR |
| 15 | Collection order | Tier 2 / IR |

**Coming next:**
- 04 Authentication anomaly
- 06 DNS tunneling
- 08 Process-creation telemetry
- 09 Discovery burst
- 10 Process injection
- 12 Persistence beyond Run keys
- 13 DLL side-loading hunt
- 14 Device-code phishing

The case file ties the shipped modules into one incident on one host:

phishing email → Mark-of-the-Web-tagged download → encoded PowerShell → obfuscated cradle → XOR-protected config → containment decision.

## Working with your own tools

Every evidence panel has a **Download evidence bundle** button. The zip holds the evidence laid out like a triage collection (per-host folders with `email/`, `logs/` and `files/`), plus a `manifest.json` with SHA-256 hashes. Use whatever you would use on the job: CyberChef (the site serves an offline copy), Python, `jq`, `xmllint` or a text editor.

## Run it locally or offline

After your first visit, the site works offline. To run it from source:

```bash
git clone https://github.com/alan-haddad/dfir-range.git
cd dfir-range
npm install
npm run build
npx vite preview          # or serve the dist/ folder with any static web server
```

To write a bundle to disk from the command line:

```bash
npm run generate -- --seed myseed --out out/myseed
```

## Privacy

There is no backend, no account, no analytics and no request to any third-party server; CI fails the build if the site makes one. Progress stays in your browser's local storage, and you can export, import or reset it. Recordings stay in the open tab unless you download them. The "grade with your own AI" feature only builds text for you to copy. It sends nothing.

## Safety

- **Synthetic and inert.** No real malware, no working payload, nothing that beacons.
- **Documentation addresses only.** IP addresses come from the RFC 5737 documentation ranges or private ranges. Domains use the reserved `.example`, `.test` and `.invalid` names.
- **Fictional people and organizations.** The victim company, its people and the attacker infrastructure are invented.
- **Checked on every change.** CI scans every generated bundle, including payloads decoded from Base64 and XOR, for real IPs, real domains and real company names, and fails the build if it finds one.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Each module is one self-contained file, and every change runs through the same checks: an independent solver must derive every answer from the evidence alone, and the inert-content scan must pass.

> The `tools/` folder contains CI tooling, including the solver. It contains spoilers.

## License

- **Code:** [MIT](LICENSE).
- **Written content** (module text, rubrics, debriefs): [CC BY 4.0](LICENSE-CONTENT).
- **CyberChef:** the bundled offline copy is © Crown Copyright and licensed under Apache-2.0.

This is a personal project for interview practice. It is not affiliated with or endorsed by any employer or organization.

# Contributing

Thanks for helping people prepare for SOC and IR interviews. This guide covers how to add a module, the rules every change must follow, and what CI checks.

## How it fits together

1. **Scenario model** (`src/world.ts`). Each seed builds one model: people, hosts, attacker infrastructure, timestamps and keys.
2. **Evidence** (`src/evidence.ts`). Every artifact renders from that model, so all the evidence agrees.
3. **Modules** (`src/modules/mNN.ts`). Each module picks the artifacts it needs, asks questions, and grades answers with forgiving normalizers (`src/lib/normalize.ts`).
4. **Answer key.** Answers are never stored; they are recomputed from the seed.

## Adding a module

Copy an existing module, such as `src/modules/m05.ts`, register it in `src/modules/index.ts`, and fill in every field:

- **Objective, background, evidence note.** Teach *why*, and name the tell.
- **Hints.** Three tiers, from a gentle nudge to nearly the method.
- **Explain-it prompt.** What the candidate should say out loud.
- **Rubric:**
  - what interviewers listen for;
  - weak, solid and strong example answers.
- **Follow-up questions and common mistakes.**
- **References.** Primary sources only: vendor documentation, RFCs, MITRE ATT&CK, NIST.
- **`build(world)`.** Returns the artifacts, the questions and a `check` function.

If the module needs new evidence, add a renderer to `src/evidence.ts` that reads from the scenario model.

## Rules

1. **Inert.**
   - No working payloads or real malware.
   - Strings that resemble live tradecraft are assembled from fragments, so the repository never contains a ready-to-run command.
2. **Documentation and private addressing only.**
   - IPs come from RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or private ranges.
   - Domains end in `.example`, `.test` or `.invalid`.
3. **Fictional organizations.**
   - No real company appears as a victim, attacker, vendor or sender.
   - Platform identifiers that real Windows telemetry requires are allowlisted in `tools/ci/inert_scan.py`.
4. **Answers come from the evidence.** Every answer must be derivable from the artifacts alone. Extend `tools/solver/solve.py` so CI proves it.
5. **Verified facts.**
   - Check every technical claim against a primary source and link it in `references`.
   - If something varies by version or product, say so instead of picking one.
6. **No answers in the README.**

## What CI checks

- **Typecheck and unit tests.** Covers determinism, IP-notation round-trips, the normalizers, and that every module accepts its own answers and rejects wrong ones across 60 seeds.
- **Solvability.** For fixed and random seeds:
  1. Generate the bundle twice and require byte-identical output.
  2. Run the independent solver on the bundle only.
  3. Grade the solver's output with the site's own checker.
- **Inert-content scan.** Covers every bundle and payload decoded from it, plus a self-test proving the scanner catches planted indicators.
- **Browser tests.** Every mode, the evidence download, offline use, and zero requests to any third-party origin.

## Local commands

```bash
npm install
npm run dev                     # local site
npm test                        # unit tests
npx playwright test             # browser tests (uses installed Google Chrome)
npm run generate -- --seed s1 --out out/s1
python3 -I tools/solver/solve.py out/s1 out/s1.json out/s1-decoded
npm run check-answers -- --seed s1 --answers out/s1.json
python3 -I tools/ci/inert_scan.py out/s1 out/s1-decoded
```

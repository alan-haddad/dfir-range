// Generate the full evidence bundle for a seed onto disk.
//   npm run generate -- --seed abc123 --out out/abc123 [--expected out/abc123.expected.json] [--zip]
// The bundle never contains answers. --expected writes them to a separate file for tests only;
// the CI solver must derive every answer from the bundle alone.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { artifactBytes, buildZip, manifest } from '../src/bundle';
import { buildCaseFile } from '../src/casefile';
import { evidenceFor } from '../src/evidence';
import { MODULES } from '../src/modules';
import { buildWorld } from '../src/world';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const seed = arg('seed');
const out = arg('out');
if (!seed || !out) {
  console.error('usage: generate --seed <seed> --out <dir> [--expected <file>] [--zip]');
  process.exit(2);
}

const w = buildWorld(seed);
const ev = evidenceFor(w);

for (const a of ev.artifacts) {
  const p = join(out, a.path);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, artifactBytes(a));
}

const instances = Object.fromEntries([...MODULES.map((m) => [m.id, m.build(w)] as const), ['case', buildCaseFile(w)] as const]);

const questions = Object.fromEntries(
  Object.entries(instances).map(([id, inst]) => [
    id,
    {
      artifacts: inst.artifacts.map((a) => a.path),
      questions: inst.questions.map((q) => ({ id: q.id, kind: q.kind, prompt: q.prompt, options: q.options, slots: q.slots })),
    },
  ]),
);
writeFileSync(join(out, 'questions.json'), JSON.stringify({ seed, modules: questions }, null, 2) + '\n');

const expectedPath = arg('expected');
if (expectedPath) {
  mkdirSync(dirname(expectedPath), { recursive: true });
  writeFileSync(expectedPath, JSON.stringify(Object.fromEntries(Object.entries(instances).map(([id, inst]) => [id, inst.expected])), null, 2) + '\n');
}

const main = async () => {
  writeFileSync(join(out, 'manifest.json'), await manifest(ev.artifacts, seed));
  if (process.argv.includes('--zip')) writeFileSync(`${out}.zip`, await buildZip(ev.artifacts, seed));
  console.log(`seed ${seed}: wrote ${ev.artifacts.length} artifacts to ${out}`);
};
main();

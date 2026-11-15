// Grade an answers file with the same check functions the site uses.
//   npm run check-answers -- --seed abc123 --answers solved.json
// Exits non-zero unless every question in every module is answered correctly.

import { readFileSync } from 'node:fs';
import { buildCaseFile } from '../src/casefile';
import { MODULES } from '../src/modules';
import type { Answer, ModuleInstance } from '../src/types';
import { buildWorld } from '../src/world';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const seed = arg('seed');
const file = arg('answers');
if (!seed || !file) {
  console.error('usage: check-answers --seed <seed> --answers <file>');
  process.exit(2);
}

const answers: Record<string, Record<string, Answer>> = JSON.parse(readFileSync(file, 'utf8'));
const w = buildWorld(seed);
const instances: [string, ModuleInstance][] = [...MODULES.map((m) => [m.id, m.build(w)] as [string, ModuleInstance]), ['case', buildCaseFile(w)]];

let failures = 0;
let total = 0;
for (const [id, inst] of instances) {
  for (const q of inst.questions) {
    total++;
    const a = answers[id]?.[q.id];
    const ok = a !== undefined && inst.check(q.id, a);
    if (!ok) {
      failures++;
      console.error(`FAIL ${id}.${q.id}: got ${JSON.stringify(a)}`);
    }
  }
}
console.log(`seed ${seed}: ${total - failures}/${total} answers accepted`);
process.exit(failures ? 1 : 0);
